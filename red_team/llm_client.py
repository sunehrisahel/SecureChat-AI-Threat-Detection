"""HTTP client for red-team LLM endpoints on the detector API (no Anthropic keys in Streamlit)."""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse, urlunparse

import requests

from attack_runner import normalize_detector_url

logger = logging.getLogger(__name__)


def _normalize_analyze_url(analyze_url: str) -> str:
    return normalize_detector_url(analyze_url.strip() or "http://127.0.0.1:8000/analyze")


def _api_base(analyze_url: str) -> str:
    parsed = urlparse(_normalize_analyze_url(analyze_url))
    return urlunparse(parsed._replace(path="", params="", query="", fragment=""))


def _red_team_url(analyze_url: str, path: str) -> str:
    base = _api_base(analyze_url).rstrip("/")
    return f"{base}{path}"


def _auth_headers(
    *,
    red_team_api_key: str = "",
    detector_api_key: str = "",
) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    token = red_team_api_key.strip() or os.getenv("RED_TEAM_API_KEY", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif detector_api_key.strip():
        headers["Authorization"] = f"Bearer {detector_api_key.strip()}"
    return headers


def _post_json(
    analyze_url: str,
    path: str,
    payload: dict,
    *,
    red_team_api_key: str = "",
    detector_api_key: str = "",
    timeout: int = 60,
) -> dict | None:
    try:
        response = requests.post(
            _red_team_url(analyze_url, path),
            json=payload,
            headers=_auth_headers(
                red_team_api_key=red_team_api_key,
                detector_api_key=detector_api_key,
            ),
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        logger.exception("Red-team LLM request failed: %s", path)
        return None


def assistant_reply(
    analyze_url: str,
    *,
    system: str,
    messages: list[dict[str, str]],
    red_team_api_key: str = "",
    detector_api_key: str = "",
) -> str:
    data = _post_json(
        analyze_url,
        "/red-team/assistant-reply",
        {"system": system, "messages": messages},
        red_team_api_key=red_team_api_key,
        detector_api_key=detector_api_key,
    )
    if not data:
        return "Assistant unavailable — check detector API and RED_TEAM_API_KEY."
    return str(data.get("text") or "Assistant returned no text.")


def explain_verdict(
    analyze_url: str,
    *,
    system: str,
    prompt: str,
    red_team_api_key: str = "",
    detector_api_key: str = "",
) -> str:
    data = _post_json(
        analyze_url,
        "/red-team/explain-verdict",
        {"system": system, "prompt": prompt},
        red_team_api_key=red_team_api_key,
        detector_api_key=detector_api_key,
    )
    if not data:
        return ""
    return str(data.get("text") or "")


def mutate_attack(
    analyze_url: str,
    *,
    base_attack: str,
    red_team_api_key: str = "",
    detector_api_key: str = "",
) -> str:
    data = _post_json(
        analyze_url,
        "/red-team/mutate-attack",
        {"base_attack": base_attack},
        red_team_api_key=red_team_api_key,
        detector_api_key=detector_api_key,
        timeout=30,
    )
    if not data:
        return base_attack
    return str(data.get("text") or base_attack)


def generate_attacks(
    analyze_url: str,
    *,
    threat_category: str,
    strategy: str,
    count: int = 5,
    red_team_api_key: str = "",
    detector_api_key: str = "",
) -> tuple[list[str], str | None]:
    data = _post_json(
        analyze_url,
        "/red-team/generate-attacks",
        {
            "threat_category": threat_category,
            "strategy": strategy,
            "count": count,
        },
        red_team_api_key=red_team_api_key,
        detector_api_key=detector_api_key,
        timeout=90,
    )
    if not data:
        return [], "Failed to reach detector API for attack generation."
    attacks = data.get("attacks") or []
    error = data.get("error")
    return [str(a) for a in attacks if a], error
