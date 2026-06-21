"""Client helpers for the detector /suggest-fix endpoint."""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)


def _normalize_analyze_url(analyze_url: str) -> str:
    """Ensure the URL targets the POST /analyze endpoint."""
    url = analyze_url.strip().rstrip("/")
    if not url:
        return "http://127.0.0.1:8000/analyze"

    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    if path in ("", "/"):
        path = "/analyze"
    elif path == "/detect":
        path = "/analyze"

    return urlunparse(parsed._replace(path=path))


def suggest_fix_url(analyze_url: str) -> str:
    """Derive the /suggest-fix URL from an /analyze endpoint URL."""
    parsed = urlparse(_normalize_analyze_url(analyze_url))
    return urlunparse(parsed._replace(path="/suggest-fix"))


def fetch_fix_suggestion(
    analyze_url: str,
    attack_text: str,
    confidence: float,
    detector_api_key: str = "",
    red_team_api_key: str = "",
) -> dict | None:
    """Request a fix suggestion from the detector /suggest-fix endpoint."""
    headers = {"Content-Type": "application/json"}
    token = red_team_api_key.strip() or os.getenv("RED_TEAM_API_KEY", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif detector_api_key.strip():
        headers["Authorization"] = f"Bearer {detector_api_key.strip()}"

    try:
        response = requests.post(
            suggest_fix_url(analyze_url),
            json={"attack_text": attack_text, "confidence": confidence},
            headers=headers,
            timeout=15,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        logger.exception("Failed to fetch fix suggestion")
        return None
