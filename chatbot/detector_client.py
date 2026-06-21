"""Client for the Prompt Injection Detector API."""

from __future__ import annotations

import logging

import requests

from config import (
    ADMIN_API_KEY,
    DETECTOR_API_KEY,
    DETECTOR_FAIL_OPEN,
    DETECTOR_TIMEOUT,
    DETECTOR_URL,
    detector_health_url,
    detector_logs_url,
)

logger = logging.getLogger(__name__)

_UNAVAILABLE = {
    "verdict": "blocked",
    "action": "block",
    "intent": "safe",
    "risk_score": 100,
    "matched_patterns": [],
    "matched_categories": [],
    "category_details": {},
    "threat_categories": [],
    "scoring_breakdown": {"detector_unavailable": True},
    "injection_probability": 0.0,
    "detector_unavailable": True,
}


def _auth_headers() -> dict[str, str]:
    if not DETECTOR_API_KEY:
        return {}
    return {"Authorization": f"Bearer {DETECTOR_API_KEY}"}


def _admin_headers() -> dict[str, str]:
    if ADMIN_API_KEY:
        return {"Authorization": f"Bearer {ADMIN_API_KEY}"}
    return _auth_headers()


def _handle_unavailable(reason: str) -> dict:
    if DETECTOR_FAIL_OPEN:
        logger.warning("Detector unavailable (%s). Fail-open enabled — allowing message.", reason)
        return {"verdict": "safe", "risk_score": 0, "action": "allow", "intent": "safe"}
    logger.error("Detector unavailable (%s). Fail-closed — blocking message.", reason)
    return dict(_UNAVAILABLE)


def check_detector_health() -> bool:
    """Return True if the detector health endpoint responds successfully."""
    try:
        response = requests.get(
            detector_health_url(),
            headers=_auth_headers(),
            timeout=DETECTOR_TIMEOUT,
        )
        response.raise_for_status()
        return True
    except (requests.ConnectionError, requests.Timeout, requests.RequestException):
        return False


def get_detector_logs() -> list:
    """Fetch recent detection logs from the detector API."""
    try:
        response = requests.get(
            detector_logs_url(),
            headers=_admin_headers(),
            timeout=DETECTOR_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, list) else []
    except (requests.ConnectionError, requests.Timeout, requests.RequestException):
        return []


def check_message(text: str, assistant_refused: bool = False) -> dict:
    """
    Send text to the detector API and return the full JSON response.

    Fail-closed by default when the detector is unreachable.
    Set DETECTOR_FAIL_OPEN=true for local dev without the detector running.
    """
    try:
        response = requests.post(
            DETECTOR_URL,
            json={
                "text": text,
                "source": "chatbot",
                "assistant_refused": assistant_refused,
            },
            headers=_auth_headers(),
            timeout=DETECTOR_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()
    except (requests.ConnectionError, requests.Timeout) as exc:
        return _handle_unavailable(exc.__class__.__name__)
    except requests.RequestException as exc:
        return _handle_unavailable(str(exc))
