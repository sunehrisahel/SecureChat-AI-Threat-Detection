"""Authentication and rate limiting for the detector API."""

from __future__ import annotations

import os
import secrets
import time
from collections import defaultdict

from fastapi import HTTPException, Request, status

DETECTOR_API_KEY = os.getenv("DETECTOR_API_KEY", "")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
RED_TEAM_API_KEY = os.getenv("RED_TEAM_API_KEY", "")
RATE_LIMIT_ANALYZE = int(os.getenv("RATE_LIMIT_ANALYZE", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))


class RateLimiter:
    """Simple in-memory sliding-window rate limiter."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        hits = [timestamp for timestamp in self._hits[key] if timestamp > window_start]
        if len(hits) >= self.max_requests:
            self._hits[key] = hits
            return False
        hits.append(now)
        self._hits[key] = hits
        return True


analyze_rate_limiter = RateLimiter(RATE_LIMIT_ANALYZE, RATE_LIMIT_WINDOW_SECONDS)


def _extract_bearer_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.headers.get("X-API-Key")


def require_detector_key(request: Request) -> None:
    """Protect /analyze when DETECTOR_API_KEY is configured."""
    if not DETECTOR_API_KEY:
        return
    token = _extract_bearer_token(request)
    if not token or not secrets.compare_digest(token, DETECTOR_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Detector API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_admin_key(request: Request) -> None:
    """Protect /logs and /analytics when ADMIN_API_KEY is configured."""
    if not ADMIN_API_KEY:
        return
    token = _extract_bearer_token(request)
    if not token or not secrets.compare_digest(token, ADMIN_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_red_team_key(request: Request) -> None:
    """Protect red-team endpoints when RED_TEAM_API_KEY is configured."""
    if not RED_TEAM_API_KEY:
        return
    token = _extract_bearer_token(request)
    if not token or not secrets.compare_digest(token, RED_TEAM_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Red team API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )


def enforce_analyze_rate_limit(request: Request) -> None:
    """Rate-limit /analyze by client IP."""
    client_ip = request.client.host if request.client else "unknown"
    if not analyze_rate_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )
