import time
from collections import defaultdict
from typing import Dict, List, Tuple

from fastapi import HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from server.config import settings


class SlidingWindowEntry:
    __slots__ = ("timestamps",)

    def __init__(self) -> None:
        self.timestamps: List[float] = []


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._ip_store: Dict[str, SlidingWindowEntry] = defaultdict(
            SlidingWindowEntry
        )
        self._key_store: Dict[str, SlidingWindowEntry] = defaultdict(
            SlidingWindowEntry
        )

    def _prune(self, entry: SlidingWindowEntry, window: float) -> None:
        cutoff = time.monotonic() - window
        entry.timestamps = [t for t in entry.timestamps if t > cutoff]

    def check(
        self, key: str, limit: int, window: float = 60.0, burst: int = 0
    ) -> Tuple[bool, int]:
        entry = self._key_store[key]
        self._prune(entry, window)
        current_count = len(entry.timestamps)

        burst_limit = burst if burst > 0 else limit
        if current_count >= burst_limit:
            return False, current_count

        entry.timestamps.append(time.monotonic())
        return True, current_count + 1

    def check_ip(self, ip: str) -> Tuple[bool, int]:
        return self.check(
            f"ip:{ip}",
            settings.rate_limit_per_minute,
            window=60.0,
            burst=settings.rate_limit_burst,
        )

    def check_key(self, api_key: str) -> Tuple[bool, int]:
        return self.check(
            f"key:{api_key}",
            settings.rate_limit_per_minute,
            window=60.0,
            burst=settings.rate_limit_burst,
        )


rate_limiter = InMemoryRateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        api_key = request.headers.get("X-API-Key", "")

        if api_key:
            allowed, count = rate_limiter.check_key(api_key)
        else:
            allowed, count = rate_limiter.check_ip(client_ip)

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Try again later.",
                headers={"Retry-After": "60", "X-RateLimit-Limit": str(settings.rate_limit_per_minute)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(
            max(0, settings.rate_limit_burst - count)
        )
        return response
