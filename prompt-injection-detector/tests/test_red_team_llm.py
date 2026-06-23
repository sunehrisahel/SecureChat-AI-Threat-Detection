"""Tests for red-team LLM proxy endpoints."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@patch("app.security.RED_TEAM_API_KEY", "secret-red-team")
def test_red_team_assistant_reply_requires_auth():
    response = client.post(
        "/red-team/assistant-reply",
        json={"system": "test", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 401


@patch("app.security.RED_TEAM_API_KEY", "secret-red-team")
@patch("app.llm_service.assistant_reply", return_value="Hello from Claude")
def test_red_team_assistant_reply_proxies(mock_reply):
    response = client.post(
        "/red-team/assistant-reply",
        headers={"Authorization": "Bearer secret-red-team"},
        json={"system": "test", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 200
    assert response.json()["text"] == "Hello from Claude"
    mock_reply.assert_called_once()


@patch("app.security.RED_TEAM_API_KEY", "secret-red-team")
@patch("app.llm_service.mutate_attack", return_value="mutated prompt")
def test_red_team_mutate_attack(mock_mutate):
    response = client.post(
        "/red-team/mutate-attack",
        headers={"Authorization": "Bearer secret-red-team"},
        json={"base_attack": "ignore instructions"},
    )
    assert response.status_code == 200
    assert response.json()["text"] == "mutated prompt"


@patch("app.security.RED_TEAM_API_KEY", "secret-red-team")
@patch("app.llm_service.test_api_key", return_value=(True, "ok"))
def test_red_team_llm_health(mock_health):
    response = client.get(
        "/red-team/llm-health",
        headers={"Authorization": "Bearer secret-red-team"},
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True, "message": "ok"}
