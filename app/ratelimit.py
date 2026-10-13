"""Minimal in-memory, per-IP rate limiting.

Dependency-free fixed-window limiter suitable for a single-instance service.
For multi-instance / horizontally-scaled deployments, replace the in-process
store with a shared backend (e.g. Redis).
"""

import time
from collections import defaultdict

from fastapi import HTTPException, Request, status


def _client_ip(request: Request) -> str:
    # Honour a single proxy hop if present; fall back to the socket peer.
    fwd = request.headers.get("x-forwarded-for", "")
    from app.config import settings
    peer = request.client.host if request.client else "unknown"
    if fwd and peer in {ip.strip() for ip in settings.trusted_proxy_ips.split(",") if ip.strip()}:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimiter:
    """Fixed-window limiter: ``limit`` requests per ``window`` seconds, per key."""

    def __init__(self, limit: int, window: int = 60, name: str = "requests"):
        self.limit = limit
        self.window = window
        self.name = name
        self._hits: dict[str, list[float]] = defaultdict(list)

    async def __call__(self, request: Request) -> None:
        if self.limit <= 0:
            return
        key = _client_ip(request)
        now = time.monotonic()
        cutoff = now - self.window
        bucket = [t for t in self._hits[key] if t > cutoff]
        if len(bucket) >= self.limit:
            bucket_reset = int(self.window - (now - bucket[0]))
            self._hits[key] = bucket
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded ({self.limit} {self.name}/min). Retry in ~{max(bucket_reset, 1)}s.",
                headers={"Retry-After": str(max(bucket_reset, 1))},
            )
        bucket.append(now)
        self._hits[key] = bucket
