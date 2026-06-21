"""Tests for chatbot security helpers."""

from __future__ import annotations

from typing import Optional
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from security import (
    RateLimiter,
    SessionStore,
    bump_detection_stats,
    merged_stats_payload,
    record_feed_detection,
    record_session_detection,
    require_red_team_key,
    revise_session_detection,
    _default_stats,
)


def _make_request(cookie: Optional[str] = None, headers: Optional[dict] = None) -> Request:
    header_list = []
    if cookie:
        header_list.append((b"cookie", cookie.encode()))
    for key, value in (headers or {}).items():
        header_list.append((key.lower().encode(), value.encode()))
    scope = {
        "type": "http",
        "method": "POST",
        "headers": header_list,
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


def test_session_store_creates_isolated_histories():
    store = SessionStore()
    req_a = _make_request()
    req_b = _make_request()

    id_a = store.get_session_id(req_a)
    id_b = store.get_session_id(req_b)

    store.get(id_a)["history"].append({"role": "user", "content": "hello a"})
    assert len(store.get(id_b)["history"]) == 1
    assert len(store.get(id_a)["history"]) == 2


def test_session_store_reuses_cookie():
    store = SessionStore()
    req = _make_request("securechat_session=abc-123")
    session_id = store.get_session_id(req)
    assert session_id == "abc-123"
    assert req.state.set_session_cookie is False


def test_rate_limiter_blocks_excess_requests():
    limiter = RateLimiter(max_requests=1, window_seconds=60)
    assert limiter.allow("user-1") is True
    assert limiter.allow("user-1") is False


@patch("detector_client.DETECTOR_FAIL_OPEN", False)
def test_detector_client_fail_closed():
    from detector_client import _handle_unavailable

    result = _handle_unavailable("timeout")
    assert result["detector_unavailable"] is True
    assert result["action"] == "block"


@patch("detector_client.DETECTOR_FAIL_OPEN", True)
def test_detector_client_fail_open_when_enabled():
    from detector_client import _handle_unavailable

    result = _handle_unavailable("timeout")
    assert result["action"] == "allow"


def test_merged_stats_include_feed_and_session():
    import security

    security._feed_stats = _default_stats()
    security._last_detection = {"verdict": "safe", "score": 0}

    session_stats = _default_stats()
    record_session_detection(session_stats, "safe", 10)
    record_feed_detection("high_risk", 80)

    merged = merged_stats_payload(session_stats)
    assert merged["total"] == 2
    assert merged["safe"] == 1
    assert merged["high_risk"] == 1
    assert merged["avg_score"] == 45.0
    assert merged["last_verdict"] == "high_risk"


def test_revise_session_detection_does_not_change_total():
    session_stats = _default_stats()
    record_session_detection(session_stats, "safe", 10)
    revise_session_detection(session_stats, "safe", 10, "high_risk", 85)

    assert session_stats["total"] == 1
    assert session_stats["safe"] == 0
    assert session_stats["high_risk"] == 1
    assert session_stats["last_verdict"] == "high_risk"


@patch("security.config.RED_TEAM_API_KEY", "secret-red-team")
def test_require_red_team_key_rejects_missing_token():
    with pytest.raises(HTTPException) as exc:
        require_red_team_key(_make_request())
    assert exc.value.status_code == 401


@patch("security.config.RED_TEAM_API_KEY", "secret-red-team")
def test_require_red_team_key_accepts_bearer_token():
    require_red_team_key(_make_request(headers={"Authorization": "Bearer secret-red-team"}))
