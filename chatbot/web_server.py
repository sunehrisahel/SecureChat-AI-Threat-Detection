"""
Web server for the AI Chatbot with Prompt Injection Protection.
Serves the chat UI at http://localhost:3000
"""

import sys
import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional

# Allow imports from the chatbot/ directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

import config
import detector_client
import llm_client
import response_analyzer

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - web_server - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI Chatbot Web Interface")

# CORS — allow all origins so the frontend can talk to this server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Conversation history (resets on server restart)
conversation_history: list = []

# Path to the detector's detections log
DETECTIONS_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "prompt-injection-detector",
    "logs",
    "detections.json",
)
MAX_LOG_ENTRIES = 100

# In-memory session stats (resets on server restart)
session_stats: dict = {
    "total": 0,
    "safe": 0,
    "suspicious": 0,
    "high_risk": 0,
    "blocked": 0,
    "score_sum": 0,
    "last_score": 0,
    "last_verdict": "safe",
    "mismatch_count": 0,
}


def reset_history():
    """Reset conversation history to just the system message."""
    global conversation_history
    conversation_history = [
        {"role": "system", "content": config.SYSTEM_PROMPT}
    ]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _update_session_stats(verdict: str, risk_score: int) -> None:
    """Update aggregate session stats after each /chat request."""
    session_stats["total"] += 1
    key = verdict if verdict in session_stats else "safe"
    session_stats[key] += 1
    session_stats["score_sum"] += risk_score
    session_stats["last_score"] = risk_score
    session_stats["last_verdict"] = verdict


def _read_recent_logs(limit: int = MAX_LOG_ENTRIES) -> list:
    """Read recent entries from the detector's detections.json file."""
    if not os.path.exists(DETECTIONS_LOG):
        return []

    entries = []
    try:
        with open(DETECTIONS_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed log line: %s", line[:80])
    except OSError as exc:
        logger.warning("Could not read detections log: %s", exc)
        return []

    return entries[-limit:]


# Initialize history on startup
reset_history()


# ── Request / Response models ──────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    reply: str
    verdict: str
    risk_score: int
    action: str = "allow"
    intent: str = "safe"
    matched_patterns: list
    matched_categories: list = []
    category_details: dict = {}
    threat_categories: list = []
    scoring_breakdown: dict = {}
    blocked: bool
    injection_probability: float
    assistant_refused: bool = False
    detector_response_mismatch: bool = False
    mismatch_alert: Optional[str] = None
    timestamp: str


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Check if this server and the detector are alive."""
    detector_status = "online" if detector_client.check_detector_health() else "offline"
    return {"status": "ok", "detector": detector_status}


@app.get("/stats")
async def get_stats():
    """Return aggregate session stats for the monitoring dashboard."""
    total = session_stats["total"]
    avg = round(session_stats["score_sum"] / total, 1) if total > 0 else 0
    return {
        "total": total,
        "safe": session_stats["safe"],
        "suspicious": session_stats["suspicious"],
        "high_risk": session_stats["high_risk"],
        "blocked": session_stats["blocked"],
        "avg_score": avg,
        "last_score": session_stats["last_score"],
        "last_verdict": session_stats["last_verdict"],
        "mismatch_count": session_stats["mismatch_count"],
    }


@app.get("/logs")
async def get_logs():
    """Return recent detection log entries from the detector API."""
    logs = detector_client.get_detector_logs()
    if not logs:
        logs = _read_recent_logs(MAX_LOG_ENTRIES)
    return list(reversed(logs))


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Receive a user message, check it, and return a response."""
    user_text = request.message.strip()

    if not user_text:
        return ChatResponse(
            reply="Please type a message.",
            verdict="safe",
            risk_score=0,
            matched_patterns=[],
            matched_categories=[],
            category_details={},
            scoring_breakdown={},
            blocked=False,
            injection_probability=0.0,
            timestamp=_utc_now_iso(),
        )

    processed_at = _utc_now_iso()

    # Step 1 — Run through the injection detector
    detection = detector_client.check_message(user_text)
    verdict = detection.get("verdict", "safe")
    action = detection.get("action", "allow")
    intent = detection.get("intent", "safe")
    risk_score = detection.get("risk_score", 0)
    matched_patterns = detection.get("matched_patterns", [])
    matched_categories = detection.get("matched_categories", [])
    category_details = detection.get("category_details", {})
    threat_categories = detection.get("threat_categories", [])
    scoring_breakdown = detection.get("scoring_breakdown", {})
    injection_probability = detection.get("injection_probability", 0.0)

    logger.info(
        "Message checked | intent=%s action=%s verdict=%s score=%s",
        intent,
        action,
        verdict,
        risk_score,
    )

    _update_session_stats(verdict, risk_score)

    # Step 2 — Block on explicit policy action (falls back to legacy verdicts)
    should_block = action == "block" or verdict in config.BLOCKED_VERDICTS
    if should_block:
        blocked_reply = (
            f"⚠️ Your message was blocked by the security filter "
            f"(verdict: {verdict}, score: {risk_score}). "
            f"Please rephrase your request."
        )
        return ChatResponse(
            reply=blocked_reply,
            verdict=verdict,
            risk_score=risk_score,
            action=action,
            intent=intent,
            matched_patterns=matched_patterns,
            matched_categories=matched_categories,
            category_details=category_details,
            threat_categories=threat_categories,
            scoring_breakdown=scoring_breakdown,
            blocked=True,
            injection_probability=injection_probability,
            timestamp=processed_at,
        )

    # Step 3 — Safe: add to history and call the LLM
    conversation_history.append({"role": "user", "content": user_text})

    # Trim history if needed
    system_msg = conversation_history[0]
    messages = conversation_history[1:]
    if len(messages) > config.MAX_HISTORY:
        messages = messages[-config.MAX_HISTORY:]
    conversation_history.clear()
    conversation_history.append(system_msg)
    conversation_history.extend(messages)

    reply = llm_client.get_response(conversation_history)
    conversation_history.append({"role": "assistant", "content": reply})

    assistant_refused = response_analyzer.is_assistant_refusal(reply)
    detector_response_mismatch = False
    mismatch_alert = None

    if assistant_refused and action == "allow":
        reconciled = detector_client.check_message(user_text, assistant_refused=True)
        verdict = reconciled.get("verdict", verdict)
        action = reconciled.get("action", action)
        intent = reconciled.get("intent", intent)
        risk_score = reconciled.get("risk_score", risk_score)
        matched_patterns = reconciled.get("matched_patterns", matched_patterns)
        matched_categories = reconciled.get("matched_categories", matched_categories)
        category_details = reconciled.get("category_details", category_details)
        threat_categories = reconciled.get("threat_categories", threat_categories)
        scoring_breakdown = reconciled.get("scoring_breakdown", scoring_breakdown)
        injection_probability = reconciled.get("injection_probability", injection_probability)
        detector_response_mismatch = reconciled.get("detector_response_mismatch", True)
        mismatch_alert = reconciled.get("mismatch_alert", "DETECTOR/RESPONSE MISMATCH")
        session_stats["mismatch_count"] += 1
        _update_session_stats(verdict, risk_score)
        logger.warning(
            "DETECTOR/RESPONSE MISMATCH | text=%r pre_score escalated to %s",
            user_text[:80],
            risk_score,
        )

    return ChatResponse(
        reply=reply,
        verdict=verdict,
        risk_score=risk_score,
        action=action,
        intent=intent,
        matched_patterns=matched_patterns,
        matched_categories=matched_categories,
        category_details=category_details,
        threat_categories=threat_categories,
        scoring_breakdown=scoring_breakdown,
        blocked=False,
        injection_probability=injection_probability,
        assistant_refused=assistant_refused,
        detector_response_mismatch=detector_response_mismatch,
        mismatch_alert=mismatch_alert,
        timestamp=processed_at,
    )


@app.post("/clear")
async def clear():
    """Reset the conversation history."""
    reset_history()
    logger.info("Conversation history cleared")
    return {"status": "cleared"}


# ── Static files ───────────────────────────────────────────────────────────────

# Serve index.html at the root
@app.get("/")
async def root():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))

# Mount static folder for any other assets
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🛡️  AI Chatbot Web Interface")
    print("─" * 40)
    print("Chat UI  →  http://localhost:3000")
    print("Detector →  http://localhost:8000")
    print("─" * 40 + "\n")
    uvicorn.run("web_server:app", host="0.0.0.0", port=3000, reload=True)
