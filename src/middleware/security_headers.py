"""Security Headers Middleware

Attaches security-related headers to every HTTP response to defend against Clickjacking, MIME sniffing, etc.
(covers the common SAST finding "Legacy Browser Clickjacking").

Notes:
  - X-Frame-Options: DENY together with CSP frame-ancestors 'none' as a double defence:
    forbids any site from embedding our pages via <iframe>/<frame> -> blocks Clickjacking.
    (X-Frame-Options covers legacy browsers; CSP frame-ancestors is the modern standard)
  - X-Content-Type-Options: nosniff, stops the browser from guessing the MIME type of responses.
  - Referrer-Policy: limits cross-site referrer leakage.
  - No HSTS: avoids breaking intranet deployments served over HTTP, where the browser would force an
    upgrade to HTTPS; when deployed behind HTTPS the reverse proxy can add it uniformly.

Placement: this must be the OUTERMOST user middleware (added last in create_app) so that responses
produced by other middleware -- the rate limiter's 429, CORS preflight answers -- carry the headers
too. Unhandled exceptions are turned into a 500 by Starlette's ServerErrorMiddleware, which sits
outside every user middleware; ``internal_error_handler`` covers that case.
"""
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def apply_security_headers(headers: MutableHeaders) -> None:
    """Add the security headers without overwriting any the response already set."""
    for name, value in SECURITY_HEADERS.items():
        headers.setdefault(name, value)


class SecurityHeadersMiddleware:
    """ASGI middleware: add security headers to every HTTP response (existing headers are not overwritten)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                apply_security_headers(MutableHeaders(scope=message))
            await send(message)

        await self.app(scope, receive, send_with_headers)


async def internal_error_handler(request: Request, exc: Exception) -> Response:
    """Handler for unhandled exceptions (runs inside ServerErrorMiddleware, outside every user middleware).

    Same body as Starlette's default 500, plus the security headers. ServerErrorMiddleware re-raises the
    exception after sending this response, so the traceback is still logged by the server.
    """
    response = PlainTextResponse("Internal Server Error", status_code=500)
    apply_security_headers(response.headers)
    return response
