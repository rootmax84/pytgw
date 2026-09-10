"""
Telegram API Gateway
"""

import os
import re
import json
import logging
import asyncio
import ipaddress
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any
from urllib.parse import urlparse, unquote, urlencode

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import dotenv

dotenv.load_dotenv()

# ---------------- Configuration ----------------
PORT = int(os.getenv("PORT", "8000"))
WORKERS = int(os.getenv("WORKERS", "1"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
SOCKS_PROXY = os.getenv("SOCKS_PROXY", "")
TIMEOUT = int(os.getenv("TIMEOUT", "30"))
CONNECT_TIMEOUT = int(os.getenv("CONNECT_TIMEOUT", "10"))
USER_AGENT = os.getenv("USER_AGENT", "PYTGW/1.0")
DISABLE_ACCESS_LOG = os.getenv("DISABLE_ACCESS_LOG", "true").lower() == "true"
X_CONNECTION_ID = os.getenv("X_CONNECTION_ID", "").strip()
VERSION = "1.1.0"

# Concurrency & connection pool tuning
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "200"))
MAX_KEEPALIVE_CONNECTIONS = int(os.getenv("MAX_KEEPALIVE_CONNECTIONS", "50"))

# ---------------- Trusted proxies (CIDR-aware) ----------------
TRUSTED_PROXIES_RAW = os.getenv("TRUSTED_PROXIES", "")
TRUSTED_NETWORKS = []

if TRUSTED_PROXIES_RAW.strip():
    for entry in TRUSTED_PROXIES_RAW.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            if '/' in entry:
                net = ipaddress.ip_network(entry, strict=False)
            else:
                addr = ipaddress.ip_address(entry)
                if isinstance(addr, ipaddress.IPv4Address):
                    net = ipaddress.IPv4Network(f"{entry}/32", strict=False)
                else:
                    net = ipaddress.IPv6Network(f"{entry}/128", strict=False)
            TRUSTED_NETWORKS.append(net)
        except ValueError as e:
            logging.warning(f"Invalid trusted proxy entry '{entry}': {e}")
else:
    TRUSTED_NETWORKS = [
        ipaddress.IPv4Network("127.0.0.1/32"),
        ipaddress.IPv6Network("::1/128"),
    ]

# ---------------- Logging ----------------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

if DISABLE_ACCESS_LOG:
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)


# ---------------- Helpers ----------------
def remove_token_from_log(text: str) -> str:
    pattern = r'/bot\d+:[A-Za-z0-9_\-]+/'
    return re.sub(pattern, '/bot[TOKEN_REMOVED]/', text)


def mask_token_in_string(text: str) -> str:
    pattern = r'bot\d+:[A-Za-z0-9_\-]+'
    return re.sub(pattern, 'bot[TOKEN_REMOVED]', text)


def normalize_proxy_url(proxy: str) -> str:
    proxy = (proxy or "").strip()
    if not proxy:
        return ""
    if not proxy.startswith(("socks5://", "socks5h://")):
        return f"socks5://{proxy}"
    return proxy


# ---------------- Middleware ----------------
class RealClientIPMiddleware(BaseHTTPMiddleware):
    """
    Replaces request.scope["client"] with the real client IP from
    X-Forwarded-For / X-Real-IP when the immediate peer is a trusted proxy.
    """
    async def dispatch(self, request: Request, call_next):
        client_host = request.client.host if request.client else None
        if client_host:
            try:
                client_ip = ipaddress.ip_address(client_host)
                if any(client_ip in net for net in TRUSTED_NETWORKS):
                    forwarded_for = request.headers.get("X-Forwarded-For")
                    if forwarded_for:
                        real_ip_str = forwarded_for.split(",")[0].strip()
                        try:
                            ipaddress.ip_address(real_ip_str)
                            request.scope["client"] = (
                                real_ip_str,
                                request.client.port if request.client else 0,
                            )
                        except ValueError:
                            pass
                    else:
                        real_ip_str = request.headers.get("X-Real-IP")
                        if real_ip_str:
                            try:
                                ipaddress.ip_address(real_ip_str)
                                request.scope["client"] = (
                                    real_ip_str,
                                    request.client.port if request.client else 0,
                                )
                            except ValueError:
                                pass
            except ValueError:
                pass
        return await call_next(request)


class ConnectionIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)

        if request.url.path == "/health":
            return await call_next(request)

        if X_CONNECTION_ID:
            connection_id = request.headers.get("X-Connection-Id")
            client_ip = request.client.host if request.client else "unknown"

            if connection_id:
                logger.debug(f"Received X-Connection-Id header from {client_ip}")
            else:
                logger.warning(f"Missing X-Connection-Id header from {client_ip}")

            if not connection_id or connection_id != X_CONNECTION_ID:
                logger.error(f"Invalid or missing X-Connection-Id header from {client_ip}")
                return PlainTextResponse(
                    status_code=500,
                    content="Internal server error",
                )

        return await call_next(request)


class MaskTokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if not DISABLE_ACCESS_LOG:
            masked_path = remove_token_from_log(request.url.path)
            client_ip = request.client.host if request.client else "unknown"
            logger.info(
                f"{client_ip} - {request.method} {masked_path} - {response.status_code}"
            )

        return response


# ---------------- Telegram API mirror ----------------
class TelegramApiMirror:
    """
    Stateless proxy. Uses the shared httpx.AsyncClient stored on app.state.
    Concurrency is bounded by app.state.semaphore.
    """

    async def handle_request(self, request: Request) -> Response:
        if request.method == "OPTIONS":
            return Response(status_code=200)

        path = urlparse(request.url.path).path

        token: Optional[str] = None
        method: Optional[str] = None

        match = re.match(r'^/bot([^/]+)/([^/?]+)', path)
        if match:
            token = unquote(match.group(1))
            method = match.group(2)
        else:
            match = re.match(r'^/([^/?]+)$', path)
            if match:
                method = match.group(1)

        if not method:
            return self._send_error("Not found", 404)

        if token:
            telegram_url = f"https://api.telegram.org/bot{token}/{method}"
        else:
            telegram_url = f"https://api.telegram.org/{method}"

        log_url = remove_token_from_log(telegram_url)
        client_ip = request.client.host if request.client else "unknown"
        logger.info(f"Proxying request from {client_ip} to: {log_url}")

        semaphore: asyncio.Semaphore = request.app.state.semaphore

        async with semaphore:
            max_retries = 2
            for attempt in range(max_retries + 1):
                try:
                    response = await self._send_request(request, telegram_url)
                    return Response(
                        content=response.content,
                        status_code=response.status_code,
                        media_type="application/json",
                    )
                except httpx.ConnectTimeout:
                    if attempt < max_retries:
                        logger.warning(
                            f"Connection timeout from {client_ip}, retry "
                            f"{attempt + 1}/{max_retries} for {log_url}"
                        )
                        await asyncio.sleep(1)
                        continue
                    logger.error(
                        f"Connection timeout from {client_ip} after "
                        f"{max_retries + 1} attempts"
                    )
                    return self._send_error(
                        "Connection timeout: Telegram API is not reachable. "
                        "Please check your network or proxy settings.",
                        504,
                    )
                except httpx.ReadTimeout as e:
                    logger.error(f"Read timeout from {client_ip}: {e}")
                    return self._send_error(
                        "Request timeout: Telegram API did not respond in time. "
                        "Please try again later.",
                        504,
                    )
                except httpx.ConnectError as e:
                    error_msg = mask_token_in_string(str(e)) if str(e) else "(no details)"
                    logger.error(
                        f"ConnectError from {client_ip} ({type(e).__name__}): "
                        f"{error_msg} | Full: {repr(e)}"
                    )
                    detail = (
                        self._analyze_connect_error(e)
                        if str(e)
                        else "Connection failed (no additional information available). "
                             "Check network and proxy."
                    )
                    return self._send_error(detail, 502)
                except Exception as e:
                    error_msg = mask_token_in_string(str(e))
                    logger.error(
                        f"Error from {client_ip} sending request: {error_msg}",
                        exc_info=True,
                    )
                    return self._send_error(f"Unexpected error: {error_msg}", 500)

        # Unreachable, kept for type checkers
        return self._send_error("Unexpected error", 500)

    def _analyze_connect_error(self, exc: httpx.ConnectError) -> str:
        err_str = str(exc).lower()
        if not err_str:
            return (
                "Connection failed unexpectedly. "
                "Verify network connectivity and proxy settings."
            )
        if "socks" in err_str or "proxy" in err_str:
            return (
                "Cannot connect to Telegram via the configured SOCKS5 proxy. "
                "Please verify that the proxy server is running, accessible, "
                "and allows connections to api.telegram.org:443. "
                "Check your SOCKS_PROXY environment variable."
            )
        if "name resolution" in err_str or "getaddrinfo" in err_str:
            return (
                "DNS resolution failed. Check that the server can resolve "
                "api.telegram.org or configure a working DNS."
            )
        if "connection refused" in err_str:
            return (
                "Connection refused by the target server. "
                "Telegram API may be temporarily unavailable or blocked."
            )
        if "tls" in err_str or "ssl" in err_str:
            return (
                "TLS/SSL handshake failed. The proxy might be intercepting "
                "traffic or the certificate is invalid."
            )
        return f"Connection error: {exc}"

    async def _send_request(
        self, original_request: Request, telegram_url: str
    ) -> httpx.Response:
        client: httpx.AsyncClient = original_request.app.state.http_client

        query_params = dict(original_request.query_params)

        data: Dict[str, Any] = {}
        files = []
        json_payload = None
        content: Optional[bytes] = None

        if original_request.method == "POST":
            content_type = original_request.headers.get("content-type", "").lower()

            if "application/json" in content_type:
                raw_body = await original_request.body()
                if raw_body:
                    try:
                        json_payload = json.loads(raw_body)
                        logger.debug(
                            "JSON payload: "
                            + mask_token_in_string(raw_body.decode(errors="ignore")[:200])
                        )
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON from client: {e}")
                        return self._send_error("Invalid JSON in request body", 400)

            elif (
                "multipart/form-data" in content_type
                or "application/x-www-form-urlencoded" in content_type
            ):
                # Let Starlette parse the form. Files are spooled to disk
                # by Starlette, so we don't buffer them in memory.
                try:
                    form = await original_request.form()
                except Exception as e:
                    logger.warning(f"Could not parse form: {e}")
                    return self._send_error("Invalid form data", 400)

                for key, value in form.items():
                    if hasattr(value, "filename") and value.filename:
                        file_obj = getattr(value, "file", None)
                        if file_obj is not None:
                            try:
                                file_obj.seek(0)
                            except Exception:
                                pass
                            files.append(
                                (key, (value.filename, file_obj, value.content_type))
                            )
                            logger.debug(
                                f"FILE: {key} = {value.filename} (streamed)"
                            )
                        else:
                            file_bytes = await value.read()
                            files.append(
                                (key, (value.filename, file_bytes, value.content_type))
                            )
                            logger.debug(
                                f"FILE: {key} = {value.filename} "
                                f"({len(file_bytes)} bytes)"
                            )
                    else:
                        data[key] = value
                        logger.debug(f"FIELD: {key} = {value}")

            else:
                # Unknown content-type: pass the raw body through.
                content = await original_request.body()

        logger.debug(f"Query params: {query_params}")
        logger.debug(
            f"Data fields: {list(data.keys()) if isinstance(data, dict) else 'raw'}"
        )
        logger.debug(f"File fields: {[f[0] for f in files]}")
        if json_payload is not None:
            logger.debug(
                "JSON keys: "
                + (
                    str(list(json_payload.keys()))
                    if isinstance(json_payload, dict)
                    else "scalar"
                )
            )

        if original_request.method == "GET":
            response = await client.get(telegram_url, params=query_params)
        else:
            if query_params:
                final_url = f"{telegram_url}?{urlencode(query_params)}"
            else:
                final_url = telegram_url

            if files:
                response = await client.post(final_url, data=data, files=files)
            elif json_payload is not None:
                response = await client.post(final_url, json=json_payload)
            elif data:
                response = await client.post(final_url, data=data)
            else:
                response = await client.post(final_url, content=content)

        logger.debug(f"Response status: {response.status_code}")
        if response.status_code != 200:
            logger.debug(f"Error response: {response.text[:200]}")

        return response

    def _send_error(self, message: str, code: int = 404) -> JSONResponse:
        return JSONResponse(
            status_code=code,
            content={
                "ok": False,
                "error_code": code,
                "description": message,
            },
        )


# Module-level singleton (mirror holds no per-request state)
telegram_mirror = TelegramApiMirror()


# ---------------- Lifespan ----------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting Telegram API Gateway version {VERSION}")

    logger.info(
        "X-Connection-Id validation "
        + ("enabled" if X_CONNECTION_ID else "disabled")
    )

    nets_str = ", ".join(str(net) for net in TRUSTED_NETWORKS)
    logger.info(f"Trusted proxy networks: {nets_str}")

    timeout_config = httpx.Timeout(
        timeout=TIMEOUT,
        connect=CONNECT_TIMEOUT,
        read=TIMEOUT,
        write=TIMEOUT,
    )

    limits = httpx.Limits(
        max_connections=max(MAX_CONCURRENT_REQUESTS * 2, 100),
        max_keepalive_connections=MAX_KEEPALIVE_CONNECTIONS,
    )

    client_kwargs: Dict[str, Any] = {
        "timeout": timeout_config,
        "limits": limits,
        "headers": {"User-Agent": USER_AGENT},
        "verify": True,
        "follow_redirects": True,
    }

    proxy_url = normalize_proxy_url(SOCKS_PROXY)
    if proxy_url:
        client_kwargs["proxy"] = proxy_url
        logger.info("SOCKS5 proxy configured")
    else:
        logger.info("Direct connection (no proxy)")

    app.state.http_client = httpx.AsyncClient(**client_kwargs)
    app.state.semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    logger.info(
        "Concurrency limits: "
        f"MAX_CONCURRENT_REQUESTS={MAX_CONCURRENT_REQUESTS}, "
        f"MAX_KEEPALIVE_CONNECTIONS={MAX_KEEPALIVE_CONNECTIONS}"
    )

    try:
        yield
    finally:
        logger.info("Shutting down, closing HTTP client...")
        try:
            await app.state.http_client.aclose()
        except Exception as e:
            logger.warning(f"Error closing HTTP client: {e}")
        logger.info("Shutdown complete")


# ---------------- App ----------------
app = FastAPI(title="Telegram API Gateway", lifespan=lifespan)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Connection-Id"],
    allow_credentials=True,
)

# Order preserved from the original code (last added = outermost)
app.add_middleware(RealClientIPMiddleware)
app.add_middleware(ConnectionIdMiddleware)
app.add_middleware(MaskTokenMiddleware)


# ---------------- Endpoints ----------------
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": VERSION,
        "port": PORT,
        "connection_id_required": bool(X_CONNECTION_ID),
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "OPTIONS"])
async def catch_all(request: Request, path: str):
    return await telegram_mirror.handle_request(request)


@app.post("/bot/{token}/{method}")
@app.get("/bot/{token}/{method}")
async def bot_handler(request: Request, token: str, method: str):
    return await telegram_mirror.handle_request(request)


# ---------------- Entrypoint ----------------
if __name__ == "__main__":
    import uvicorn

    if WORKERS > 1:
        # Multiple workers require the import-string form.
        # Run as a module: `python -m app.main` from the project root,
        # or `python main.py` from inside the app/ directory.
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=PORT,
            workers=WORKERS,
            log_level=LOG_LEVEL.lower(),
            access_log=not DISABLE_ACCESS_LOG,
        )
    else:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=PORT,
            log_level=LOG_LEVEL.lower(),
            access_log=not DISABLE_ACCESS_LOG,
        )
