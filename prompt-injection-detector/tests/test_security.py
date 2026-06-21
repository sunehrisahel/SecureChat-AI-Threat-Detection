"""Tests for detector API security helpers."""

from __future__ import annotations

from typing import Optional
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.security import RateLimiter, require_admin_key, require_detector_key, require_red_team_key


def _make_request(headers: Optional[dict] = None) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


def test_rate_limiter_blocks_after_max_requests():
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-a") is False


def test_rate_limiter_isolated_by_key():
    limiter = RateLimiter(max_requests=1, window_seconds=60)
    assert limiter.allow("client-a") is True
    assert limiter.allow("client-b") is True


@patch("app.security.DETECTOR_API_KEY", "secret-detector")
def test_require_detector_key_rejects_missing_token():
    with pytest.raises(HTTPException) as exc:
        require_detector_key(_make_request())
    assert exc.value.status_code == 401


@patch("app.security.DETECTOR_API_KEY", "secret-detector")
def test_require_detector_key_accepts_bearer_token():
    require_detector_key(_make_request({"Authorization": "Bearer secret-detector"}))


@patch("app.security.DETECTOR_API_KEY", "")
def test_require_detector_key_skips_when_unconfigured():
    require_detector_key(_make_request())


@patch("app.security.ADMIN_API_KEY", "secret-admin")
def test_require_admin_key_rejects_missing_token():
    with pytest.raises(HTTPException) as exc:
        require_admin_key(_make_request())
    assert exc.value.status_code == 401


@patch("app.security.ADMIN_API_KEY", "secret-admin")
def test_require_admin_key_accepts_bearer_token():
    require_admin_key(_make_request({"Authorization": "Bearer secret-admin"}))


@patch("app.security.RED_TEAM_API_KEY", "secret-red-team")
def test_require_red_team_key_rejects_missing_token():
    with pytest.raises(HTTPException) as exc:
        require_red_team_key(_make_request())
    assert exc.value.status_code == 401


@patch("app.security.RED_TEAM_API_KEY", "secret-red-team")
def test_require_red_team_key_accepts_bearer_token():
    require_red_team_key(_make_request({"Authorization": "Bearer secret-red-team"}))
