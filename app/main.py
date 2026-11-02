"""
Telegram API Gateway
"""

import os
import re
import json
import logging
import asyncio
import ipaddress
import secrets
import random
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any, Union
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
VERSION = "1.2.1"

# OpenAPI/Swagger/ReDoc endpoints are disabled by default. They
# reveal the gateway's routing structure to unauthenticated clients and
# are not needed in production. Set ENABLE_DOCS=true to re-enable.
ENABLE_DOCS = os.getenv("ENABLE_DOCS", "false").lower() == "true"

# Concurrency & connection pool tuning
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "200"))
MAX_KEEPALIVE_CONNECTIONS = int(os.getenv("MAX_KEEPALIVE_CONNECTIONS", "50"))

# Maximum allowed request body size (in bytes). Default: 20 MiB.
# Telegram's bot API caps file uploads at ~20 MiB for most methods.
MAX_REQUEST_BODY_SIZE = int(os.getenv("MAX_REQUEST_BODY_SIZE", str(20 * 1024 * 1024)))

# retry tuning. Exponential backoff with full jitter avoids the
# "thundering herd" pattern when Telegram has a brief outage.
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "2"))
RETRY_BASE_DELAY = float(os.getenv("RETRY_BASE_DELAY", "0.5"))
RETRY_MAX_DELAY = float(os.getenv("RETRY_MAX_DELAY", "5.0"))

# CORS is now configurable via env. The previous hard-coded
# `allow_origins=["*"]` + `allow_credentials=True` combination is invalid
# per the CORS spec — browsers reject it. We keep the wildcard default but
# disable credentials, and expose both knobs for operators who need them.
CORS_ALLOW_ORIGINS_RAW = os.getenv("CORS_ALLOW_ORIGINS", "*").strip()
CORS_ALLOW_ORIGINS = (
    ["*"]
    if CORS_ALLOW_ORIGINS_RAW == "*"
    else [o.strip() for o in CORS_ALLOW_ORIGINS_RAW.split(",") if o.strip()]
)
CORS_ALLOW_CREDENTIALS = (
    os.getenv("CORS_ALLOW_CREDENTIALS", "false").lower() == "true"
)

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
    # Default: only localhost is trusted.
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

# Silence noisy third-party loggers.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# uvicorn's default access logger prints the raw URL path, which
# leaks the bot token into logs. Always silence it. Access logging is
# handled by MaskTokenMiddleware below, which masks tokens before logging.
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("uvicorn.error").setLevel(logging.INFO)


# ---------------- Helpers ----------------
def remove_token_from_log(text: str) -> str:
    """Replace the bot token in a URL/path with a placeholder for safe logging."""
    pattern = r'/bot\d+:[A-Za-z0-9_\-]+/'
    return re.sub(pattern, '/bot[TOKEN_REMOVED]/', text)


def mask_token_in_string(text: str) -> str:
    """Replace any bot token appearing anywhere in a string with a placeholder."""
    pattern = r'bot\d+:[A-Za-z0-9_\-]+'
    return re.sub(pattern, 'bot[TOKEN_REMOVED]', text)


def normalize_proxy_url(proxy: str) -> str:
    """Normalize a SOCKS proxy string into a full URL with a scheme."""
    proxy = (proxy or "").strip()
    if not proxy:
        return ""
    if not proxy.startswith(("socks5://", "socks5h://")):
        return f"socks5://{proxy}"
    return proxy


def is_valid_bot_token(token: str) -> bool:
    """
    Validate the shape of a Telegram bot token.
    Format: <digits>:<alphanumeric_with_dashes_and_underscores>
    """
    return bool(re.match(r'^\d+:[A-Za-z0-9_\-]+$', token))


def _compute_backoff(attempt: int) -> float:
    """
    Exponential backoff with full jitter.
    Returns a random delay in [0, min(base * 2**attempt, max_delay)].
    """
    exp = RETRY_BASE_DELAY * (2 ** attempt)
    capped = min(exp, RETRY_MAX_DELAY)
    return random.uniform(0, capped)


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
    """
    Enforces the X-Connection-Id header when X_CONNECTION_ID is configured.
    Returns 403 Forbidden on mismatch/missing header (semantically correct).
    """
    async def dispatch(self, request: Request, call_next):
        # Preflight and health checks bypass the header check.
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

            # constant-time comparison to prevent timing attacks
            # on the shared secret. Both sides are encoded to bytes first,
            # so non-ASCII inputs simply fail the match rather than crash.
            matches = False
            if connection_id:
                try:
                    matches = secrets.compare_digest(
                        connection_id.encode("utf-8"),
                        X_CONNECTION_ID.encode("utf-8"),
                    )
                except (TypeError, ValueError):
                    matches = False

            if not matches:
                logger.error(
                    f"Invalid or missing X-Connection-Id header from {client_ip}"
                )
                # 403 Forbidden is more accurate than 500 for auth failures.
                return PlainTextResponse(
                    status_code=403,
                    content="Forbidden: invalid or missing X-Connection-Id",
                )

        return await call_next(request)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Rejects requests whose declared body size exceeds MAX_REQUEST_BODY_SIZE.

    Uses Content-Length when available. Chunked requests without a
    Content-Length header are not blocked here; the underlying
    httpx client and Starlette form parsing will still stream them.
    """
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_REQUEST_BODY_SIZE:
                    logger.warning(
                        f"Rejecting request from "
                        f"{request.client.host if request.client else 'unknown'}: "
                        f"body too large ({content_length} bytes)"
                    )
                    return JSONResponse(
                        status_code=413,
                        content={
                            "ok": False,
                            "error_code": 413,
                            "description": (
                                f"Request body too large. Maximum allowed: "
                                f"{MAX_REQUEST_BODY_SIZE} bytes."
                            ),
                        },
                    )
            except ValueError:
                # Malformed Content-Length header; let downstream handle it.
                pass
        return await call_next(request)


class MaskTokenMiddleware(BaseHTTPMiddleware):
    """
    Logs requests with tokens masked and (optionally) preserves uvicorn
    access log behavior.
    """
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

        # Try /bot<token>/<method> first.
        match = re.match(r'^/bot([^/]+)/([^/?]+)', path)
        if match:
            token = unquote(match.group(1))
            method = match.group(2)
            # Validate token shape before forwarding to Telegram.
            if not is_valid_bot_token(token):
                logger.warning(
                    f"Rejecting request with malformed bot token from "
                    f"{request.client.host if request.client else 'unknown'}"
                )
                return self._send_error("Invalid bot token format", 400)
        else:
            # Fall back to a bare method path, e.g. /getMe (rare, for tests).
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
            for attempt in range(MAX_RETRIES + 1):
                try:
                    result = await self._send_request(request, telegram_url)

                    # `_send_request` may return a starlette
                    # JSONResponse when the incoming body cannot be parsed
                    # (e.g. invalid JSON / malformed form). Return it
                    # directly — do NOT access `.content`, which only
                    # exists on httpx.Response and would raise AttributeError.
                    if isinstance(result, JSONResponse):
                        return result

                    return self._forward_response(result)

                except httpx.ConnectTimeout:
                    if attempt < MAX_RETRIES:
                        # exponential backoff with full jitter.
                        delay = _compute_backoff(attempt)
                        logger.warning(
                            f"Connection timeout from {client_ip}, retry "
                            f"{attempt + 1}/{MAX_RETRIES} for {log_url} "
                            f"after {delay:.2f}s"
                        )
                        await asyncio.sleep(delay)
                        continue
                    logger.error(
                        f"Connection timeout from {client_ip} after "
                        f"{MAX_RETRIES + 1} attempts"
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

        # Unreachable, kept for type checkers.
        return self._send_error("Unexpected error", 500)

    def _forward_response(self, response: httpx.Response) -> Response:
        """
        Copy an upstream httpx response into a Starlette Response
        while preserving important headers (Content-Type, Content-Disposition,
        Retry-After).

        Note: Content-Encoding is intentionally NOT forwarded — httpx has
        already transparently decoded the body (it advertises
        Accept-Encoding: gzip, deflate, br, zstd by default), so forwarding
        the original Content-Encoding header would instruct the client to
        decompress already-decompressed bytes.
        """
        passthrough_headers: Dict[str, str] = {}
        for header in (
            "content-type",
            "content-disposition",
            "retry-after",
        ):
            value = response.headers.get(header)
            if value is not None:
                passthrough_headers[header] = value

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=passthrough_headers,
        )

    def _analyze_connect_error(self, exc: httpx.ConnectError) -> str:
        """Map a ConnectError to a human-readable diagnostic message."""
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
    ) -> Union[httpx.Response, JSONResponse]:
        """
        Forward the incoming request to Telegram and return the httpx response.

        return type is now Union[httpx.Response, JSONResponse] to
        reflect that parse errors are surfaced as starlette JSONResponse
        objects (handled by the caller).
        """
        client: httpx.AsyncClient = original_request.app.state.http_client

        # Preserve query string parameters (e.g. ?offset=... for getUpdates).
        query_params = dict(original_request.query_params)

        data: Dict[str, Any] = {}
        files = []
        json_payload = None
        content: Optional[bytes] = None
        # remember the client's Content-Type so it can be preserved
        # when passing raw bytes through for unknown content types.
        original_ct = original_request.headers.get("content-type", "")

        if original_request.method == "POST":
            content_type = original_ct.lower()

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
                        # UploadedFile-like: prefer streaming from the underlying file.
                        file_obj = getattr(value, "file", None)
                        if file_obj is not None:
                            try:
                                # rewind before each attempt so
                                # retries never send a truncated file.
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
                            # Small in-memory file.
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
                # Unknown content-type: pass the raw body through untouched.
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
            # Append query params to URL for POST requests.
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
                # preserve the client's Content-Type when passing
                # raw bytes (or an empty body) through to Telegram. Some
                # endpoint behaviors depend on Content-Type being present.
                raw_headers: Dict[str, str] = {}
                if original_ct:
                    raw_headers["Content-Type"] = original_ct
                response = await client.post(
                    final_url,
                    content=content if content is not None else b"",
                    headers=raw_headers,
                )

        logger.debug(f"Response status: {response.status_code}")
        if response.status_code != 200:
            logger.debug(f"Error response: {response.text[:200]}")

        return response

    def _send_error(self, message: str, code: int = 404) -> JSONResponse:
        """Return a Telegram-style error JSON response."""
        return JSONResponse(
            status_code=code,
            content={
                "ok": False,
                "error_code": code,
                "description": message,
            },
        )


# Module-level singleton (mirror holds no per-request state).
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
    logger.info(f"Max request body size: {MAX_REQUEST_BODY_SIZE} bytes")

    # log retry policy so operators can see what's active.
    logger.info(
        f"Retry policy: MAX_RETRIES={MAX_RETRIES}, "
        f"RETRY_BASE_DELAY={RETRY_BASE_DELAY}s, "
        f"RETRY_MAX_DELAY={RETRY_MAX_DELAY}s"
    )

    timeout_config = httpx.Timeout(
        timeout=TIMEOUT,
        connect=CONNECT_TIMEOUT,
        read=TIMEOUT,
        write=TIMEOUT,
    )

    # Connection pool sizing:
    #   max_connections  = concurrency budget + keep-alive headroom
    #   max_keepalive    = keep idle sockets warm for reuse
    limits = httpx.Limits(
        max_connections=MAX_CONCURRENT_REQUESTS + MAX_KEEPALIVE_CONNECTIONS,
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
# docs/openapi endpoints are opt-in to reduce attack surface.
# Set ENABLE_DOCS=true to expose /docs, /redoc and /openapi.json.
if ENABLE_DOCS:
    app = FastAPI(
        title="Telegram API Gateway",
        version=VERSION,
        lifespan=lifespan,
    )
else:
    app = FastAPI(
        title="Telegram API Gateway",
        version=VERSION,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

# CORS
# allow_credentials=True combined with allow_origins=["*"] is
# rejected by all modern browsers per the CORS spec. We validate the
# combination and fall back to credentials=False with a warning, so
# misconfiguration can't silently break clients.
if CORS_ALLOW_CREDENTIALS and CORS_ALLOW_ORIGINS == ["*"]:
    logger.warning(
        "CORS: allow_credentials=True with allow_origins='*' is invalid per "
        "spec and will be ignored by browsers. Falling back to "
        "credentials=False. Set CORS_ALLOW_ORIGINS explicitly to enable "
        "credentials."
    )
    CORS_ALLOW_CREDENTIALS = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Connection-Id"],
    allow_credentials=CORS_ALLOW_CREDENTIALS,
)

# Middleware order: last added is outermost.
# Execution order (outermost -> innermost):
#   1. MaskTokenMiddleware   (logging)
#   2. ConnectionIdMiddleware (auth gate)
#   3. BodySizeLimitMiddleware (DoS guard)
#   4. RealClientIPMiddleware  (rewrites client IP)
app.add_middleware(RealClientIPMiddleware)
app.add_middleware(BodySizeLimitMiddleware)
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


# Declared BEFORE catch_all so FastAPI matches it first.
# Route order in FastAPI follows declaration order.
@app.post("/bot/{token}/{method}")
@app.get("/bot/{token}/{method}")
async def bot_handler(request: Request, token: str, method: str):
    return await telegram_mirror.handle_request(request)


# Catch-all: registered last so it only handles unmatched paths.
@app.api_route("/{path:path}", methods=["GET", "POST", "OPTIONS"])
async def catch_all(request: Request, path: str):
    return await telegram_mirror.handle_request(request)


# ---------------- Entrypoint ----------------
if __name__ == "__main__":
    import uvicorn

    # uvicorn's own access log prints raw URL paths (including bot tokens).
    # It is ALWAYS disabled here. Masked access logging is provided by
    # MaskTokenMiddleware and controlled by DISABLE_ACCESS_LOG.
    # Passing `access_log=False` prevents uvicorn's dictConfig() from
    # re-enabling the handler after our module-level setLevel() call,
    # which would otherwise leak raw tokens when running `python main.py`.
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
            access_log=False,
        )
    else:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=PORT,
            log_level=LOG_LEVEL.lower(),
            access_log=False,
        )
