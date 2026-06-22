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
    VERCEL_PROTECTION_BYPASS,
    detector_health_url,
    detector_logs_url,
)
import inline_detector

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


def _request_headers(*, admin: bool = False) -> dict[str, str]:
    headers = dict(_admin_headers() if admin else _auth_headers())
    if VERCEL_PROTECTION_BYPASS:
        headers["x-vercel-protection-bypass"] = VERCEL_PROTECTION_BYPASS
    return headers


def _handle_unavailable(reason: str) -> dict:
    if DETECTOR_FAIL_OPEN:
        logger.warning("Detector unavailable (%s). Fail-open enabled — allowing message.", reason)
        return {"verdict": "safe", "risk_score": 0, "action": "allow", "intent": "safe"}
    logger.error("Detector unavailable (%s). Fail-closed — blocking message.", reason)
    return dict(_UNAVAILABLE)


def _health_failure_hint(response: requests.Response | None, exc: Exception | None = None) -> str:
    if response is not None and response.status_code == 401:
        body = response.text[:500].lower()
        if "vercel.com/sso" in body or "sso-api" in body:
            return (
                "Vercel Deployment Protection is blocking the detector. "
                "Disable it on the detector project, or set VERCEL_PROTECTION_BYPASS "
                "on this chatbot to the detector project's bypass secret."
            )
        return "Detector returned 401 — check DETECTOR_API_KEY matches the detector project."
    if exc is not None:
        return f"Cannot reach detector at {detector_health_url()}: {exc}"
    return f"Detector health check failed at {detector_health_url()}."


def probe_detector_health() -> tuple[bool, str | None]:
    """Return (online, error_hint). error_hint is set when offline."""
    if inline_detector.should_use_inline():
        return True, None

    try:
        response = requests.get(
            detector_health_url(),
            headers=_request_headers(),
            timeout=DETECTOR_TIMEOUT,
        )
        if response.status_code == 401:
            return False, _health_failure_hint(response)
        response.raise_for_status()
        return True, None
    except (requests.ConnectionError, requests.Timeout) as exc:
        return False, _health_failure_hint(None, exc)
    except requests.RequestException as exc:
        response = getattr(exc, "response", None)
        if response is not None:
            return False, _health_failure_hint(response, exc)
        return False, _health_failure_hint(None, exc)


def check_detector_health() -> bool:
    """Return True if the detector health endpoint responds successfully."""
    online, _ = probe_detector_health()
    return online


def get_detector_logs() -> list:
    """Fetch recent detection logs from the detector API."""
    try:
        response = requests.get(
            detector_logs_url(),
            headers=_request_headers(admin=True),
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
    if inline_detector.should_use_inline():
        try:
            return inline_detector.analyze(
                text,
                source="chatbot",
                assistant_refused=assistant_refused,
            )
        except Exception as exc:
            logger.exception("Inline detector failed: %s", exc)
            return _handle_unavailable(str(exc))

    try:
        response = requests.post(
            DETECTOR_URL,
            json={
                "text": text,
                "source": "chatbot",
                "assistant_refused": assistant_refused,
            },
            headers=_request_headers(),
            timeout=DETECTOR_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()
    except requests.HTTPError as exc:
        response = getattr(exc, "response", None)
        if response is not None and response.status_code == 401:
            body = response.text[:800].lower()
            if "vercel.com/sso" in body or "sso-api" in body or "vercel authentication" in body:
                if inline_detector.is_available():
                    try:
                        return inline_detector.analyze(
                            text,
                            source="chatbot",
                            assistant_refused=assistant_refused,
                        )
                    except Exception as inline_exc:
                        return _handle_unavailable(str(inline_exc))
                return _handle_unavailable(
                    "Vercel Deployment Protection — set VERCEL_PROTECTION_BYPASS or disable protection on detector"
                )
        return _handle_unavailable(str(exc))
    except (requests.ConnectionError, requests.Timeout) as exc:
        if inline_detector.is_available():
            try:
                return inline_detector.analyze(
                    text,
                    source="chatbot",
                    assistant_refused=assistant_refused,
                )
            except Exception as inline_exc:
                return _handle_unavailable(str(inline_exc))
        return _handle_unavailable(exc.__class__.__name__)
    except requests.RequestException as exc:
        return _handle_unavailable(str(exc))
