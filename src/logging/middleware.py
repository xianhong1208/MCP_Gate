"""Request Logging Middleware

Automatically logs all HTTP requests with timing and context.
"""

import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from src.logging.logger import (
    get_logger,
    set_request_context,
    clear_request_context,
    generate_request_id,
)

logger = get_logger("http")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs all HTTP requests with timing information"""

    def __init__(self, app, exclude_paths: list[str] = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or ["/health", "/metrics"]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate request ID
        request_id = request.headers.get("X-Request-ID") or generate_request_id()

        # Set request context for logging
        set_request_context(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=self._get_client_ip(request),
        )

        # Add request ID to response headers
        start_time = time.perf_counter()

        try:
            response = await call_next(request)

            # Calculate request duration
            duration_ms = (time.perf_counter() - start_time) * 1000

            # Log request (skip excluded paths for cleaner logs)
            if request.url.path not in self.exclude_paths:
                self._log_request(
                    request=request,
                    response=response,
                    duration_ms=duration_ms,
                    request_id=request_id,
                )

            # Add request ID to response
            response.headers["X-Request-ID"] = request_id

            return response

        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                f"Request failed: {request.method} {request.url.path}",
                error=str(e),
                duration_ms=round(duration_ms, 2),
            )
            raise

        finally:
            # Clear request context
            clear_request_context()

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, considering proxies"""
        # Check X-Forwarded-For header first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()

        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to direct client IP
        if request.client:
            return request.client.host

        return "unknown"

    def _log_request(
        self,
        request: Request,
        response: Response,
        duration_ms: float,
        request_id: str,
    ):
        """Log the completed request"""
        status_code = response.status_code

        # Determine log level based on status code
        if status_code >= 500:
            log_func = logger.error
        elif status_code >= 400:
            log_func = logger.warning
        else:
            log_func = logger.info

        log_func(
            f"{request.method} {request.url.path} -> {status_code}",
            status_code=status_code,
            duration_ms=round(duration_ms, 2),
            user_agent=request.headers.get("User-Agent", "")[:100],
        )
