"""CORS for the public OAuth protocol endpoints.

The console's CORS policy is deliberately narrow (its own origins, with credentials). The OAuth
protocol surface is different: discovery documents, dynamic client registration and the token
endpoint are meant to be called by *any* client, including MCP hosts that run the flow in the
browser. Those requests carry no cookies, so answering `Access-Control-Allow-Origin: *` for these
paths is safe and is what RFC 8414 / RFC 9728 clients expect. Everything else keeps the console
policy.
"""

from typing import Iterable

PUBLIC_PREFIXES: tuple[str, ...] = ("/.well-known/",)
PUBLIC_PATHS: tuple[str, ...] = ("/oauth/register", "/oauth/token", "/oauth/revoke", "/oauth/introspect")

_HEADERS = {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "Authorization, Content-Type, Mcp-Protocol-Version",
    "access-control-max-age": "3600",
}


def is_public_oauth_path(path: str) -> bool:
    return path.startswith(PUBLIC_PREFIXES) or path in PUBLIC_PATHS


def _encode(headers: dict[str, str]) -> list[tuple[bytes, bytes]]:
    return [(k.encode(), v.encode()) for k, v in headers.items()]


class PublicOAuthCORSMiddleware:
    """Outermost ASGI middleware: answers preflights and stamps `*` CORS headers on public OAuth paths."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not is_public_oauth_path(scope["path"]):
            await self.app(scope, receive, send)
            return

        if scope["method"] == "OPTIONS":
            await send({"type": "http.response.start", "status": 204, "headers": _encode(_HEADERS)})
            await send({"type": "http.response.body", "body": b""})
            return

        async def send_with_cors(message):
            if message["type"] == "http.response.start":
                present: Iterable[bytes] = {k.lower() for k, _ in message.get("headers", [])}
                # The console policy may already have answered for one of its own origins; do not
                # contradict it. Otherwise open the document to every origin.
                if b"access-control-allow-origin" not in present:
                    message = {**message, "headers": list(message.get("headers", [])) + _encode(_HEADERS)}
            await send(message)

        await self.app(scope, receive, send_with_cors)
