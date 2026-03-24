"""
Telegram API Gateway
"""

import os
import re
import json
import logging
import asyncio
from typing import Optional, Dict, Any
from urllib.parse import parse_qs, urlparse, unquote, urlencode

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import dotenv

dotenv.load_dotenv()

# Configuration
PORT = int(os.getenv("PORT", "8000"))
WORKERS = int(os.getenv("WORKERS", "1"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
SOCKS_PROXY = os.getenv("SOCKS_PROXY", "")
TIMEOUT = int(os.getenv("TIMEOUT", "30"))
CONNECT_TIMEOUT = int(os.getenv("CONNECT_TIMEOUT", "10"))
USER_AGENT = os.getenv("USER_AGENT", "PYTGW/1.0")
DISABLE_ACCESS_LOG = os.getenv("DISABLE_ACCESS_LOG", "true").lower() == "true"
X_CONNECTION_ID = os.getenv("X_CONNECTION_ID", "").strip()

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress noisy loggers
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

if DISABLE_ACCESS_LOG:
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)

app = FastAPI(title="Telegram API Gateway")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Connection-Id"],
    allow_credentials=True,
)

class ConnectionIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip validation for OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Skip validation for health check endpoint if X_CONNECTION_ID is set
        if request.url.path == "/health":
            return await call_next(request)

        # Check if X-Connection-Id validation is required
        if X_CONNECTION_ID:
            connection_id = request.headers.get("X-Connection-Id")

            # Log the received connection ID (masked for security)
            if connection_id:
                logger.debug(f"Received X-Connection-Id header")
            else:
                logger.warning(f"Missing X-Connection-Id header")

            # Validate connection ID
            if not connection_id or connection_id != X_CONNECTION_ID:
                logger.error(f"Invalid or missing X-Connection-Id header")
                return PlainTextResponse(
                    status_code=500,
                    content="Internal server error"
                )

        # Proceed with the request
        response = await call_next(request)
        return response

class MaskTokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if not DISABLE_ACCESS_LOG:
            original_path = request.url.path
            masked_path = remove_token_from_log(original_path)
            logger.info(f"{request.method} {masked_path} - {response.status_code}")

        return response

def remove_token_from_log(text: str) -> str:
    pattern = r'/bot\d+:[A-Za-z0-9_\-]+/'
    return re.sub(pattern, '/bot[TOKEN_REMOVED]/', text)


def mask_token_in_string(text: str) -> str:
    pattern = r'bot\d+:[A-Za-z0-9_\-]+'
    return re.sub(pattern, 'bot[TOKEN_REMOVED]', text)

# Add middlewares (order matters - ConnectionIdMiddleware should be first)
app.add_middleware(ConnectionIdMiddleware)
app.add_middleware(MaskTokenMiddleware)

class TelegramApiMirror:
    def __init__(self, socks_proxy: Optional[str] = None):
        self.socks_proxy = socks_proxy
        self.timeout = TIMEOUT
        self.connect_timeout = CONNECT_TIMEOUT
        self.user_agent = USER_AGENT

    async def handle_request(self, request: Request) -> Response:
        # Handle OPTIONS
        if request.method == "OPTIONS":
            return Response(status_code=200)

        # Parse URL path
        path = urlparse(request.url.path).path

        # Extract token and method
        token = None
        method = None

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

        # Build Telegram URL
        if token:
            telegram_url = f"https://api.telegram.org/bot{token}/{method}"
        else:
            telegram_url = f"https://api.telegram.org/{method}"

        # Log with token removed
        log_url = remove_token_from_log(telegram_url)
        logger.info(f"Proxying request to: {log_url}")

        # Send request to Telegram with retry
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                response = await self._send_request(request, telegram_url)
                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    media_type="application/json"
                )
            except httpx.ConnectTimeout as e:
                if attempt < max_retries:
                    logger.warning(f"Connection timeout, retry {attempt + 1}/{max_retries} for {log_url}")
                    await asyncio.sleep(1)  # Wait 1 second before retry
                    continue
                else:
                    logger.error(f"Connection timeout after {max_retries + 1} attempts")
                    return self._send_error("Connection timeout", 504)
            except httpx.ReadTimeout as e:
                logger.error(f"Read timeout: {e}")
                return self._send_error("Request timeout", 504)
            except Exception as e:
                error_msg = mask_token_in_string(str(e))
                logger.error(f"Error sending request: {error_msg}", exc_info=True)
                return self._send_error(str(e), 500)

    async def _send_request(self, original_request: Request, telegram_url: str) -> httpx.Response:
        """Send request to Telegram API"""

        # Get query parameters from original URL
        query_params = dict(original_request.query_params)

        # Prepare data and files from body
        data = {}
        files = []

        if original_request.method == "POST":
            # Use request.form() which properly handles multipart
            try:
                form = await original_request.form()

                for key, value in form.items():
                    if hasattr(value, 'filename') and value.filename:
                        # This is a file
                        content = await value.read()
                        files.append(
                            (key, (value.filename, content, value.content_type))
                        )
                        logger.debug(f"FILE: {key} = {value.filename} ({len(content)} bytes)")
                    else:
                        # This is a regular field
                        data[key] = value
                        logger.debug(f"FIELD: {key} = {value}")
            except Exception as e:
                logger.error(f"Error parsing form: {e}", exc_info=True)

        # Log what we're sending
        logger.debug(f"Query params: {query_params}")
        logger.debug(f"Data fields: {list(data.keys())}")
        logger.debug(f"File fields: {[f[0] for f in files]}")

        # Configure client with separate timeouts
        timeout_config = httpx.Timeout(
            timeout=self.timeout,
            connect=self.connect_timeout,
            read=self.timeout,
            write=self.timeout
        )

        client_kwargs = {
            "timeout": timeout_config,
            "headers": {"User-Agent": self.user_agent},
            "verify": True,
            "follow_redirects": True
        }

        if self.socks_proxy:
            client_kwargs["proxies"] = {
                "http://": f"socks5://{self.socks_proxy}",
                "https://": f"socks5://{self.socks_proxy}"
            }

        async with httpx.AsyncClient(**client_kwargs) as client:
            if original_request.method == "GET":
                response = await client.get(telegram_url, params=query_params)
            elif files:
                # POST with files
                if query_params:
                    final_url = f"{telegram_url}?{urlencode(query_params)}"
                else:
                    final_url = telegram_url

                logger.debug(f"Sending POST with {len(files)} file(s)")
                response = await client.post(final_url, data=data, files=files)
            elif data:
                # POST with data only
                if query_params:
                    final_url = f"{telegram_url}?{urlencode(query_params)}"
                else:
                    final_url = telegram_url

                logger.debug(f"Sending POST with data only")
                response = await client.post(final_url, data=data)
            else:
                # POST without data
                if query_params:
                    final_url = f"{telegram_url}?{urlencode(query_params)}"
                else:
                    final_url = telegram_url

                response = await client.post(final_url)

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
                "description": message
            }
        )

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "port": PORT, "connection_id_required": bool(X_CONNECTION_ID)}

# Main handler for all routes
@app.api_route("/{path:path}", methods=["GET", "POST", "OPTIONS"])
async def catch_all(request: Request, path: str):
    mirror = TelegramApiMirror(socks_proxy=SOCKS_PROXY if SOCKS_PROXY else None)
    return await mirror.handle_request(request)

# Direct bot handler
@app.post("/bot/{token}/{method}")
@app.get("/bot/{token}/{method}")
async def bot_handler(request: Request, token: str, method: str):
    mirror = TelegramApiMirror(socks_proxy=SOCKS_PROXY if SOCKS_PROXY else None)
    return await mirror.handle_request(request)

if __name__ == "__main__":
    import uvicorn

    if X_CONNECTION_ID:
        logger.info(f"X-Connection-Id validation enabled")
    else:
        logger.info("X-Connection-Id validation disabled")

    if SOCKS_PROXY:
        logger.info(f"SOCKS5 proxy configured: {SOCKS_PROXY}")
    else:
        logger.info("Direct connection (no proxy)")

    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=PORT,
        workers=WORKERS,
        log_level=LOG_LEVEL.lower(),
        access_log=not DISABLE_ACCESS_LOG,
    )
