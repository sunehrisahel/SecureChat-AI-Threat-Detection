"""Authentication, rate limiting, and session management for the chatbot."""

from __future__ import annotations

import secrets
import time
import uuid
from collections import defaultdict
from typing import Any

from fastapi import HTTPException, Request, status

import config

SESSION_COOKIE = "securechat_session"


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


def _default_stats() -> dict[str, Any]:
    return {
        "total": 0,
        "safe": 0,
        "suspicious": 0,
        "high_risk": 0,
        "blocked": 0,
        "score_sum": 0,
        "last_score": 0,
        "last_verdict": "safe",
        "mismatch_count": 0,
    }


_VERDICT_KEYS = ("safe", "suspicious", "high_risk", "blocked")
_COUNT_KEYS = ("total", "safe", "suspicious", "high_risk", "blocked", "score_sum")
_feed_stats: dict[str, Any] = _default_stats()
_last_detection: dict[str, Any] = {"verdict": "safe", "score": 0}


def _verdict_bucket(verdict: str) -> str:
    return verdict if verdict in _VERDICT_KEYS else "safe"


def bump_detection_stats(stats: dict[str, Any], verdict: str, risk_score: int) -> None:
    """Increment aggregate counters for one analyzed message."""
    stats["total"] += 1
    stats[_verdict_bucket(verdict)] += 1
    stats["score_sum"] += risk_score
    stats["last_score"] = risk_score
    stats["last_verdict"] = verdict


def note_last_detection(verdict: str, risk_score: int) -> None:
    """Track the most recent detection for merged /stats responses."""
    global _last_detection
    _last_detection = {"verdict": verdict, "score": risk_score}


def record_session_detection(session_stats: dict[str, Any], verdict: str, risk_score: int) -> None:
    """Record a user-initiated /chat detection."""
    bump_detection_stats(session_stats, verdict, risk_score)
    note_last_detection(verdict, risk_score)


def record_feed_detection(verdict: str, risk_score: int) -> None:
    """Record a red-team injected detection visible to all SecureChat viewers."""
    bump_detection_stats(_feed_stats, verdict, risk_score)
    note_last_detection(verdict, risk_score)


def revise_session_detection(
    session_stats: dict[str, Any],
    old_verdict: str,
    old_score: int,
    new_verdict: str,
    new_score: int,
) -> None:
    """Adjust session stats after detector/response reconciliation (no total bump)."""
    old_key = _verdict_bucket(old_verdict)
    new_key = _verdict_bucket(new_verdict)
    session_stats[old_key] = max(0, session_stats[old_key] - 1)
    session_stats[new_key] += 1
    session_stats["score_sum"] += new_score - old_score
    session_stats["last_score"] = new_score
    session_stats["last_verdict"] = new_verdict
    note_last_detection(new_verdict, new_score)


def merged_stats_payload(session_stats: dict[str, Any]) -> dict[str, Any]:
    """Merge per-session stats with global live-feed detections."""
    merged = {key: session_stats.get(key, 0) + _feed_stats.get(key, 0) for key in _COUNT_KEYS}
    total = merged["total"]
    return {
        "total": total,
        "safe": merged["safe"],
        "suspicious": merged["suspicious"],
        "high_risk": merged["high_risk"],
        "blocked": merged["blocked"],
        "avg_score": round(merged["score_sum"] / total, 1) if total > 0 else 0,
        "last_score": _last_detection["score"],
        "last_verdict": _last_detection["verdict"],
        "mismatch_count": session_stats.get("mismatch_count", 0),
    }


class SessionStore:
    """Per-session conversation history and stats."""

    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}

    def get_session_id(self, request: Request) -> str:
        session_id = request.cookies.get(SESSION_COOKIE)
        if not session_id:
            session_id = str(uuid.uuid4())
        request.state.session_id = session_id
        request.state.set_session_cookie = SESSION_COOKIE not in request.cookies
        return session_id

    def get(self, session_id: str) -> dict[str, Any]:
        if session_id not in self._sessions:
            self._sessions[session_id] = {
                "history": [{"role": "system", "content": config.SYSTEM_PROMPT}],
                "stats": _default_stats(),
            }
        return self._sessions[session_id]

    def reset(self, session_id: str) -> None:
        self._sessions[session_id] = {
            "history": [{"role": "system", "content": config.SYSTEM_PROMPT}],
            "stats": _default_stats(),
        }


chat_rate_limiter = RateLimiter(config.RATE_LIMIT_CHAT, config.RATE_LIMIT_WINDOW_SECONDS)
session_store = SessionStore()


def _extract_bearer_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.headers.get("X-API-Key")


def require_admin_key(request: Request) -> None:
    """Protect sensitive endpoints when ADMIN_API_KEY is configured."""
    if not config.ADMIN_API_KEY:
        return
    token = _extract_bearer_token(request)
    if not token or not secrets.compare_digest(token, config.ADMIN_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_red_team_key(request: Request) -> None:
    """Protect red-team inject endpoints when RED_TEAM_API_KEY is configured."""
    if not config.RED_TEAM_API_KEY:
        return
    token = _extract_bearer_token(request)
    if not token or not secrets.compare_digest(token, config.RED_TEAM_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Red team API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )


def enforce_chat_rate_limit(request: Request) -> None:
    """Rate-limit /chat by session (or client IP as fallback)."""
    session_id = getattr(request.state, "session_id", None)
    client_ip = request.client.host if request.client else "unknown"
    key = session_id or client_ip
    if not chat_rate_limiter.allow(key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait before sending more messages.",
        )


def apply_session_cookie(request: Request, response) -> None:
    """Attach the session cookie on first visit."""
    if getattr(request.state, "set_session_cookie", False):
        response.set_cookie(
            SESSION_COOKIE,
            request.state.session_id,
            httponly=True,
            samesite="lax",
            secure=config.COOKIE_SECURE,
        )
