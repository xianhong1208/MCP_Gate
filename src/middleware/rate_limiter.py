"""Rate Limiter Middleware

IP-based request rate limiting to prevent API abuse.
Implemented with a sliding-window algorithm.
"""

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.utils.client_ip import is_ip_in_whitelist, resolve_client_ip

__all__ = ["is_ip_in_whitelist", "RateLimitConfig", "RateLimiter", "RateLimitMiddleware"]


@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    requests_per_minute: int = 60  # Maximum requests per minute
    requests_per_hour: int = 1000  # Maximum requests per hour
    burst_size: int = 10  # Allowed burst size
    enabled: bool = True
    # Whitelisted IPs (not rate limited)
    whitelist: list = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    # Custom limits for specific paths
    path_limits: Dict[str, int] = field(default_factory=dict)
    # Trusted reverse-proxy IPs (X-Forwarded-For is only parsed for requests coming from these IPs)
    trusted_proxies: list = field(default_factory=lambda: ["127.0.0.1", "::1"])


class SlidingWindowCounter:
    """Sliding-window counter"""

    def __init__(self, window_size: int = 60):
        self.window_size = window_size  # Window size (seconds)
        self.requests: Dict[str, list] = defaultdict(list)

    def add_request(self, key: str) -> int:
        """Record a request and return the request count within the window."""
        now = time.time()
        window_start = now - self.window_size

        # Drop expired request records
        self.requests[key] = [t for t in self.requests[key] if t > window_start]

        # Record the current request
        self.requests[key].append(now)

        return len(self.requests[key])

    def get_count(self, key: str) -> int:
        """Get the request count within the current window."""
        now = time.time()
        window_start = now - self.window_size
        self.requests[key] = [t for t in self.requests[key] if t > window_start]
        return len(self.requests[key])

    def cleanup(self):
        """Purge all expired records."""
        now = time.time()
        for key in list(self.requests.keys()):
            window_start = now - self.window_size
            self.requests[key] = [t for t in self.requests[key] if t > window_start]
            if not self.requests[key]:
                del self.requests[key]


class RateLimiter:
    """Rate limiter instance"""

    _instance: Optional['RateLimiter'] = None

    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig()
        self.minute_counter = SlidingWindowCounter(window_size=60)
        self.hour_counter = SlidingWindowCounter(window_size=3600)
        self.blocked_until: Dict[str, float] = {}  # Blocked IPs
        self._lock = asyncio.Lock()  # Guards concurrent access

    @classmethod
    def get_instance(cls, config: RateLimitConfig = None) -> 'RateLimiter':
        """Get the singleton instance."""
        if cls._instance is None:
            cls._instance = cls(config)
        return cls._instance

    @classmethod
    def reset_instance(cls):
        """Reset the instance (for tests)."""
        cls._instance = None

    async def is_allowed(self, client_ip: str, path: str = None) -> tuple[bool, str, int]:
        """
        Check whether a request is allowed.

        Returns:
            (allowed, reason, retry_after)
        """
        if not self.config.enabled:
            return True, "", 0

        # Whitelist check (CIDR supported) -- no lock needed
        if is_ip_in_whitelist(client_ip, self.config.whitelist):
            return True, "", 0

        async with self._lock:
            # Check whether temporarily blocked
            if client_ip in self.blocked_until:
                if time.time() < self.blocked_until[client_ip]:
                    retry_after = int(self.blocked_until[client_ip] - time.time())
                    return False, "too_many_requests", retry_after
                else:
                    del self.blocked_until[client_ip]

            # Get the limit values
            minute_limit = self.config.requests_per_minute
            hour_limit = self.config.requests_per_hour

            # Specific paths may have custom limits
            if path and path in self.config.path_limits:
                minute_limit = self.config.path_limits[path]

            # Check the per-minute limit
            minute_count = self.minute_counter.add_request(f"{client_ip}:minute")
            if minute_count > minute_limit:
                # Limit exceeded; block temporarily for 60 seconds
                self.blocked_until[client_ip] = time.time() + 60
                return False, "rate_limit_minute", 60

            # Check the per-hour limit
            hour_count = self.hour_counter.add_request(f"{client_ip}:hour")
            if hour_count > hour_limit:
                # Hourly limit exceeded; block until the next hour
                self.blocked_until[client_ip] = time.time() + 300  # 5 minutes
                return False, "rate_limit_hour", 300

            return True, "", 0

    def get_stats(self, client_ip: str) -> dict:
        """Get request statistics for a client."""
        return {
            "minute_count": self.minute_counter.get_count(f"{client_ip}:minute"),
            "minute_limit": self.config.requests_per_minute,
            "hour_count": self.hour_counter.get_count(f"{client_ip}:hour"),
            "hour_limit": self.config.requests_per_hour,
            "is_blocked": client_ip in self.blocked_until,
        }


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI rate limit middleware"""

    def __init__(self, app, config: RateLimitConfig = None):
        super().__init__(app)
        self.config = config or RateLimitConfig()
        self.limiter = RateLimiter.get_instance(config)
        # Paths that are not rate limited
        self.excluded_paths = ["/docs", "/redoc", "/openapi.json", "/health"]

    async def dispatch(self, request: Request, call_next):
        # Skip excluded paths
        if any(request.url.path.startswith(p) for p in self.excluded_paths):
            return await call_next(request)

        # Get the client IP
        client_ip = self._get_client_ip(request)

        # Check whether allowed
        allowed, reason, retry_after = await self.limiter.is_allowed(
            client_ip,
            request.url.path
        )

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": f"Too many requests. Please retry after {retry_after} seconds.",
                    "reason": reason,
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)}
            )

        # Add rate limit headers
        response = await call_next(request)
        stats = self.limiter.get_stats(client_ip)
        response.headers["X-RateLimit-Limit"] = str(stats["minute_limit"])
        response.headers["X-RateLimit-Remaining"] = str(
            max(0, stats["minute_limit"] - stats["minute_count"])
        )

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Get the client's real IP.

        Forwarded headers are only honoured when the direct peer is a trusted proxy, and X-Forwarded-For is
        read right to left (see src.utils.client_ip), so a forged header can neither dodge the limit nor
        frame another address.
        """
        return resolve_client_ip(request, self.config.trusted_proxies) or "unknown"
