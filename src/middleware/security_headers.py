"""Security Headers Middleware

Attaches security-related headers to every HTTP response to defend against Clickjacking, MIME sniffing, etc.
Prevents Clickjacking / MIME sniffing (covers the common SAST finding "Legacy Browser Clickjacking").

Notes:
  - X-Frame-Options: DENY together with CSP frame-ancestors 'none' as a double defence:
    forbids any site from embedding our pages via <iframe>/<frame> -> blocks Clickjacking.
    (X-Frame-Options covers legacy browsers; CSP frame-ancestors is the modern standard)
  - X-Content-Type-Options: nosniff, stops the browser from guessing the MIME type of responses.
  - Referrer-Policy: limits cross-site referrer leakage.
  - No HSTS: avoids breaking intranet deployments served over HTTP, where the browser would force an
    upgrade to HTTPS; when deployed behind HTTPS the reverse proxy can add it uniformly.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every response (uses setdefault, so existing headers are not overwritten)."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        headers = response.headers
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response
