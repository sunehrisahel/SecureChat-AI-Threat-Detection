"""In-memory queue of red-team messages injected into SecureChat."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import config
import detector_client
import llm_client

RED_TEAM_SESSION_ID = "red-team-live-feed"

_injection_feed: list[dict[str, Any]] = []
_next_id = 0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _should_block(detection: dict, verdict: str) -> bool:
    action = detection.get("action", "allow")
    if detection.get("detector_unavailable"):
        return True
    if config.BLOCK_WARN_ACTION and action == "warn":
        return True
    if action == "block":
        return True
    return verdict in config.BLOCKED_VERDICTS


def _blocked_reply(verdict: str, risk_score: int) -> str:
    return (
        f"⚠️ Your message was blocked by the security filter "
        f"(verdict: {verdict}, score: {risk_score}). "
        f"Please rephrase your request."
    )


def append_injected_message(
    content: str,
    verdict: str,
    session_store,
) -> dict[str, Any]:
    """Store an injected attack, run detector + Claude, and queue for the UI."""
    global _next_id

    detection = detector_client.check_message(content)
    risk_score = int(detection.get("risk_score", 0))
    blocked = _should_block(detection, detection.get("verdict", "safe"))

    session = session_store.get(RED_TEAM_SESSION_ID)
    assistant_reply = None

    if blocked:
        assistant_reply = _blocked_reply(detection.get("verdict", verdict), risk_score)
    else:
        history = session["history"]
        history.append({"role": "user", "content": content})
        assistant_reply = llm_client.get_response(history)
        history.append({"role": "assistant", "content": assistant_reply})
        if len(history) > config.MAX_HISTORY + 1:
            session["history"] = [history[0], *history[-config.MAX_HISTORY :]]

    detector_verdict = detection.get("verdict", verdict)

    entry = {
        "id": _next_id,
        "content": content,
        "injected": True,
        "verdict": verdict,
        "detector_verdict": detector_verdict,
        "risk_score": risk_score,
        "confidence": float(
            detection.get("threat_confidence")
            or detection.get("intent_confidence")
            or 0.0
        ),
        "matched_patterns": detection.get("matched_patterns", []),
        "matched_categories": detection.get("matched_categories", []),
        "category_details": detection.get("category_details", {}),
        "scoring_breakdown": detection.get("scoring_breakdown", {}),
        "injection_probability": float(detection.get("injection_probability", 0.0)),
        "blocked": blocked,
        "assistant_reply": assistant_reply,
        "timestamp": _utc_now_iso(),
    }
    _next_id += 1
    _injection_feed.append(entry)

    if len(_injection_feed) > 500:
        del _injection_feed[:-500]

    return entry


def get_messages_since(since: int) -> dict[str, Any]:
    """Return injected messages with id greater than or equal to since."""
    messages = [item for item in _injection_feed if item["id"] >= since]
    return {"messages": messages, "next_since": _next_id}
