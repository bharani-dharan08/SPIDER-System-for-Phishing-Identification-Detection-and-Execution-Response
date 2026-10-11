"""
SPIDER API Rate Limiting Middleware
Provides sliding-window token bucket rate limiting for FastAPI backend.
Protects detection engine endpoints against exhaustion attacks & high-volume abuse.
"""

import time
import logging
from typing import Dict, List, Tuple, Optional, Any
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger("spider.rate_limiter")
logger.setLevel(logging.INFO)


class APIRateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        global_max_requests: int = 100,
        analysis_max_requests: int = 30,
        window_seconds: int = 60,
        exempt_paths: Optional[List[str]] = None,
    ):
        super().__init__(app)
        self.global_max_requests = global_max_requests
        self.analysis_max_requests = analysis_max_requests
        self.window_seconds = window_seconds
        self.exempt_paths = exempt_paths or ["/health", "/api/health", "/docs", "/openapi.json", "/redoc"]
        
        # IP -> List of timestamps for global requests
        self._global_buckets: Dict[str, List[float]] = {}
        # IP -> List of timestamps for high-cost analysis requests
        self._analysis_buckets: Dict[str, List[float]] = {}
        
        # Endpoints considered high-cost analysis requests
        self.analysis_endpoints = {
            "/api/analyze/spider-engine",
            "/api/analyze/late-fusion",
            "/api/upload/audio",
            "/api/upload/image",
            "/api/upload/email",
            "/api/upload/text",
        }

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP handling forward proxies."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    def _prune_and_count(
        self, bucket: Dict[str, List[float]], key: str, now: float, window: int
    ) -> Tuple[int, float]:
        """
        Removes timestamps outside the window and returns current count 
        plus time in seconds until the oldest request in the window expires.
        """
        timestamps = bucket.get(key, [])
        cutoff = now - window
        # Filter active timestamps within the current sliding window
        valid_timestamps = [t for t in timestamps if t > cutoff]
        bucket[key] = valid_timestamps

        count = len(valid_timestamps)
        if count > 0:
            oldest = valid_timestamps[0]
            reset_seconds = max(1, int(window - (now - oldest)))
        else:
            reset_seconds = window

        return count, reset_seconds

    def _clean_stale_buckets(self, now: float):
        """Clean up empty IP buckets to conserve memory."""
        cutoff = now - self.window_seconds
        for b in (self._global_buckets, self._analysis_buckets):
            stale_keys = [k for k, v in b.items() if not v or v[-1] <= cutoff]
            for k in stale_keys:
                del b[k]

    def get_stats(self) -> Dict[str, Any]:
        """Returns rate limiter metrics for health monitoring."""
        now = time.time()
        self._clean_stale_buckets(now)
        return {
            "rate_limiting_active": True,
            "global_max_requests_per_min": self.global_max_requests,
            "analysis_max_requests_per_min": self.analysis_max_requests,
            "window_seconds": self.window_seconds,
            "tracked_global_ips": len(self._global_buckets),
            "tracked_analysis_ips": len(self._analysis_buckets),
        }

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        now = time.time()
        
        # Always allow CORS preflight requests
        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path

        # Check exempt paths
        if any(path.startswith(exempt) for exempt in self.exempt_paths):
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        self._clean_stale_buckets(now)

        is_analysis_route = path in self.analysis_endpoints or path.startswith("/api/analyze/") or path.startswith("/api/upload/")
        max_limit = self.analysis_max_requests if is_analysis_route else self.global_max_requests
        bucket = self._analysis_buckets if is_analysis_route else self._global_buckets

        current_count, reset_seconds = self._prune_and_count(bucket, client_ip, now, self.window_seconds)

        if current_count >= max_limit:
            logger.warning(
                f"[SPIDER RATE LIMIT EXCEEDED] IP={client_ip} Path={path} "
                f"Count={current_count}/{max_limit} ResetIn={reset_seconds}s"
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": (
                        f"High-volume detection engine protection active. "
                        f"Maximum {max_limit} requests per {self.window_seconds}s window allowed for this endpoint. "
                        f"Retry in {reset_seconds} seconds."
                    ),
                    "retry_after_seconds": reset_seconds,
                    "limit": max_limit,
                    "window_seconds": self.window_seconds,
                    "endpoint": path,
                    "client_ip": client_ip,
                },
                headers={
                    "Retry-After": str(reset_seconds),
                    "X-RateLimit-Limit": str(max_limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_seconds),
                    "X-RateLimit-Protection": "SPIDER-FastAPI-Guard",
                },
            )

        # Record this request timestamp
        if client_ip not in bucket:
            bucket[client_ip] = []
        bucket[client_ip].append(now)

        remaining = max(0, max_limit - (current_count + 1))

        response = await call_next(request)

        # Inject RateLimit headers into response
        response.headers["X-RateLimit-Limit"] = str(max_limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_seconds)
        response.headers["X-RateLimit-Protection"] = "SPIDER-FastAPI-Guard"

        return response
