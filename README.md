# PYTGW - Telegram API Gateway

![CI History](https://img.shields.io/github/actions/workflow/status/rootmax84/pytgw/.github/workflows/docker-image.yml?branch=main&label=build%20history&style=flat-round)

A lightweight, high-performance Telegram Bot API proxy/gateway written in Python. It acts as a reverse proxy for Telegram Bot API requests, supporting both direct and SOCKS5 proxy connections.

## Features

-  **Full Telegram Bot API Support** - Proxies all Telegram Bot API methods
-  **URL-Encoded Token Support** - Handles URL-encoded bot tokens in paths
-  **File Upload Support** - Properly handles multipart/form-data file uploads (photos, documents, etc.)
-  **SOCKS5 Proxy Support** - Route requests through SOCKS5 proxy
-  **Masking** - Optional security header and dummy page for illegitimate requests
-  **Token Masking** - Automatically removes bot tokens from logs for security
-  **Async Performance** - Built with FastAPI and httpx for high concurrency
-  **Health Check** - Built-in health check endpoint for container orchestration
-  **Automatic Retries** - Retries failed requests on connection timeouts
-  **Configurable Logging** - Adjustable log levels and access log control

## Quick Start

```bash
git clone https://github.com/rootmax84/pytgw.git
cd pytgw
docker-compose up -d
```

or use this compose

```bash
services:
  pytgw:
    image: rootmax84/pytgw:latest
    ports:
      - "9999:8000"
    environment:
      - WORKERS=1
      - PORT=8000
      - LOG_LEVEL=info
      - DISABLE_ACCESS_LOG=true
      - SOCKS_PROXY=
      - TIMEOUT=30
      - CONNECT_TIMEOUT=10
      - USER_AGENT=PYTGW/1.0
      - X_CONNECTION_ID=
    restart: always
    healthcheck:
      test: ["CMD-SHELL", "PORT=$${PORT:-8000}; curl -f http://localhost:$$PORT/health || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 30s
```

## Gateway masking example via nginx (SWAG)
```bash
server {
    listen 443 quic;
    listen 443 ssl;

    server_name ...;

    location / {
        include /config/nginx/proxy.conf;
        include /config/nginx/resolver.conf;
        set $upstream_app pytgw;
        set $upstream_port 8000;
        set $upstream_proto http;
        proxy_pass $upstream_proto://$upstream_app:$upstream_port;
        proxy_intercept_errors on;
        error_page 500 =500 /dummy_page.html; #empty/wrong X-Connection-Id
    }

    error_page 500 /dummy_page.html;
        location = /dummy_page.html {
            root /config/www;
            internal;
    }
}
```

## Environment Variables
or use this compose

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Application port | `8000` |
| `WORKERS` | Uvicorn workers count | `1` |
| `LOG_LEVEL` | Logging level (critical, error, warning, info, debug, trace) | `info` |
| `DISABLE_ACCESS_LOG` | Disable uvicorn access logs | `true` |
| `SOCKS_PROXY` | SOCKS5 proxy (format: ip:port) | (empty) |
| `TIMEOUT` | Request timeout in seconds | `30` |
| `CONNECT_TIMEOUT` | Connection timeout in seconds | `10` |
| `USER_AGENT` | Custom User-Agent header | `PYTGW/1.0` |
| `X_CONNECTION_ID` | Security header that must be present in the client request | (empty) |

## Testing
```bash
# Get bot information
curl http://localhost:9999/bot<TOKEN>/getMe

# Send a message
curl -X POST http://localhost:9999/bot<TOKEN>/sendMessage \
  -d "chat_id=123456789" \
  -d "text=Hello from PYTGW"
```
