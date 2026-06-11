"""Client for the local Prompt Injection Detector API."""

from __future__ import annotations

import requests

from config import DETECTOR_TIMEOUT, DETECTOR_URL

DETECTOR_HEALTH_URL = "http://localhost:8000/health"


def check_detector_health() -> bool:
    """Return True if the detector health endpoint responds successfully."""
    try:
        response = requests.get(DETECTOR_HEALTH_URL, timeout=DETECTOR_TIMEOUT)
        response.raise_for_status()
        return True
    except (requests.ConnectionError, requests.Timeout, requests.RequestException):
        return False


def check_message(text: str, assistant_refused: bool = False) -> dict:
    """
    Send text to the detector API and return the full JSON response.

    If the detector is unreachable, fail open with a safe verdict so the
    chatbot can continue operating.
    """
    try:
        response = requests.post(
            DETECTOR_URL,
            json={
                "text": text,
                "source": "chatbot",
                "assistant_refused": assistant_refused,
            },
            timeout=DETECTOR_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()
    except (requests.ConnectionError, requests.Timeout) as exc:
        print(f"Warning: Detector unreachable ({exc.__class__.__name__}). Allowing message.")
        return {"verdict": "safe", "risk_score": 0}
    except requests.RequestException as exc:
        print(f"Warning: Detector request failed ({exc}). Allowing message.")
        return {"verdict": "safe", "risk_score": 0}
