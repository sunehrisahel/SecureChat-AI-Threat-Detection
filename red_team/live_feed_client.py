"""Client for the detector /fire-attack live feed endpoint."""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse, urlunparse

import requests

from attack_runner import normalize_detector_url

logger = logging.getLogger(__name__)


def fire_attack_url(analyze_url: str) -> str:
    """Derive the /fire-attack URL from an /analyze endpoint URL."""
    parsed = urlparse(normalize_detector_url(analyze_url))
    return urlunparse(parsed._replace(path="/fire-attack"))


def fire_attack(
    analyze_url: str,
    attack_text: str,
    delay_ms: int = 1500,
    detector_api_key: str = "",
    red_team_api_key: str = "",
) -> dict | None:
    """Fire a single attack through the detector live-feed pipeline."""
    headers = {"Content-Type": "application/json"}
    token = red_team_api_key.strip() or os.getenv("RED_TEAM_API_KEY", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif detector_api_key.strip():
        # Backward compatibility when only detector key was configured.
        headers["Authorization"] = f"Bearer {detector_api_key.strip()}"

    try:
        response = requests.post(
            fire_attack_url(analyze_url),
            json={"attack_text": attack_text, "delay_ms": delay_ms},
            headers=headers,
            timeout=120,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        logger.exception("Failed to fire attack")
        return None
