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
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import config
import detector_client
import injection_feed
import llm_client
import response_analyzer
from security import (
    apply_session_cookie,
    enforce_chat_rate_limit,
    merged_stats_payload,
    record_feed_detection,
    record_session_detection,
    require_admin_key,
    require_red_team_key,
    revise_session_detection,
    session_store,
)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - web_server - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI Chatbot Web Interface")

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Path to the detector's detections log (local dev fallback)
DETECTIONS_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "prompt-injection-detector",
    "logs",
    "detections.json",
)
MAX_LOG_ENTRIES = 100
MAX_PANEL_LOG = 50
_panel_log: list[dict] = []
_panel_log_seq = 0


def _append_panel_log(
    text: str,
    detection: dict,
    timestamp: Optional[str] = None,
    session_scope: str = "feed",
) -> None:
    """Keep a recent in-memory log for the SecureChat detection panel."""
    global _panel_log_seq
    entry = {
        "id": _panel_log_seq,
        "text": text,
        "verdict": detection.get("verdict", "safe"),
        "risk_score": int(detection.get("risk_score", 0)),
        "matched_patterns": detection.get("matched_patterns", []),
        "matched_categories": detection.get("matched_categories", []),
        "category_details": detection.get("category_details", {}),
        "scoring_breakdown": detection.get("scoring_breakdown", {}),
        "injection_probability": float(detection.get("injection_probability", 0.0)),
        "timestamp": timestamp or _utc_now_iso(),
        "session_scope": session_scope,
    }
    _panel_log_seq += 1
    _panel_log.insert(0, entry)
    if len(_panel_log) > MAX_PANEL_LOG:
        del _panel_log[MAX_PANEL_LOG:]


@app.middleware("http")
async def attach_session(request: Request, call_next):
    session_store.get_session_id(request)
    response = await call_next(request)
    apply_session_cookie(request, response)
    return response


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _detection_payload(detection: dict) -> dict:
    """Extract fields stored in the panel log from a detector response."""
    return {
        "verdict": detection.get("verdict", "safe"),
        "risk_score": int(detection.get("risk_score", 0)),
        "matched_patterns": detection.get("matched_patterns", []),
        "matched_categories": detection.get("matched_categories", []),
        "category_details": detection.get("category_details", {}),
        "scoring_breakdown": detection.get("scoring_breakdown", {}),
        "injection_probability": float(detection.get("injection_probability", 0.0)),
    }


def _trim_history(history: list) -> list:
    system_msg = history[0]
    messages = history[1:]
    if len(messages) > config.MAX_HISTORY:
        messages = messages[-config.MAX_HISTORY :]
    return [system_msg, *messages]


def _read_recent_logs(limit: int = MAX_LOG_ENTRIES) -> list:
    """Read recent detection logs from the detector API or local file."""
    if os.getenv("VERCEL") or os.getenv("DETECTOR_URL", "").startswith("http"):
        return detector_client.get_detector_logs()[:limit]

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


def _should_block_message(detection: dict, action: str, verdict: str) -> bool:
    if detection.get("detector_unavailable"):
        return True
    if config.BLOCK_WARN_ACTION and action == "warn":
        return True
    if action == "block":
        return True
    return verdict in config.BLOCKED_VERDICTS


def _blocked_reply(detection: dict, verdict: str, risk_score: int) -> str:
    if detection.get("detector_unavailable"):
        return (
            "⚠️ Security check is temporarily unavailable. "
            "Your message was blocked for safety. Please try again shortly."
        )
    if config.BLOCK_WARN_ACTION and detection.get("action") == "warn":
        return (
            f"⚠️ Your message was flagged as suspicious "
            f"(verdict: {verdict}, score: {risk_score}) and blocked. "
            f"Please rephrase your request."
        )
    return (
        f"⚠️ Your message was blocked by the security filter "
        f"(verdict: {verdict}, score: {risk_score}). "
        f"Please rephrase your request."
    )


# ── Request / Response models ──────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str = Field(..., max_length=4000)


class InjectMessageRequest(BaseModel):
    content: str = Field(..., max_length=4000)
    injected: bool = True
    verdict: str = Field(..., pattern="^(safe|suspicious|prompt_injection)$")


class InjectMessageResponse(BaseModel):
    id: int
    content: str
    injected: bool
    verdict: str
    detector_verdict: str
    risk_score: int
    confidence: float
    matched_patterns: list = Field(default_factory=list)
    matched_categories: list = Field(default_factory=list)
    category_details: dict = Field(default_factory=dict)
    scoring_breakdown: dict = Field(default_factory=dict)
    injection_probability: float = 0.0
    blocked: bool
    assistant_reply: Optional[str]
    timestamp: str


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
    online, hint = detector_client.probe_detector_health()
    payload = {"status": "ok", "detector": "online" if online else "offline"}
    if hint:
        payload["detector_hint"] = hint
    return payload


@app.post("/api/inject-message", response_model=InjectMessageResponse)
async def inject_message(
    body: InjectMessageRequest,
    _: None = Depends(require_red_team_key),
):
    """Accept a red-team injected message and queue it for the chat UI."""
    entry = injection_feed.append_injected_message(
        body.content,
        body.verdict,
        session_store,
    )
    logger.info(
        "Injected red-team message id=%s verdict=%s blocked=%s",
        entry["id"],
        entry["verdict"],
        entry["blocked"],
    )
    record_feed_detection(entry["detector_verdict"], entry["risk_score"])
    _append_panel_log(
        body.content,
        {
            "verdict": entry["detector_verdict"],
            "risk_score": entry["risk_score"],
            "matched_patterns": entry["matched_patterns"],
            "matched_categories": entry["matched_categories"],
            "category_details": entry["category_details"],
            "scoring_breakdown": entry["scoring_breakdown"],
            "injection_probability": entry["injection_probability"],
        },
        entry["timestamp"],
        session_scope="feed",
    )
    return InjectMessageResponse(**entry)


@app.get("/api/detection-log")
async def get_panel_detection_log(request: Request, since: int = 0):
    """Return recent detections for the SecureChat sidebar (no admin key)."""
    session_id = request.state.session_id
    visible = [
        item
        for item in _panel_log
        if item.get("session_scope") in ("feed", session_id)
    ]
    if since:
        entries = [item for item in visible if item["id"] >= since]
        return {"entries": entries, "next_since": _panel_log_seq}
    return visible


@app.get("/api/injected-messages")
async def injected_messages(since: int = 0):
    """Poll endpoint used by SecureChat to receive injected attack messages."""
    return injection_feed.get_messages_since(since)


@app.get("/stats")
async def get_stats(request: Request):
    """Return aggregate stats for the current browser session."""
    session = session_store.get(request.state.session_id)
    return merged_stats_payload(session["stats"])


@app.get("/logs")
async def get_logs(_: None = Depends(require_admin_key)):
    """Return recent detection log entries (admin only when ADMIN_API_KEY is set)."""
    logs = detector_client.get_detector_logs()
    if not logs:
        logs = _read_recent_logs(MAX_LOG_ENTRIES)
    return list(reversed(logs))


@app.post("/chat", response_model=ChatResponse)
async def chat(request: Request, body: ChatRequest):
    """Receive a user message, check it, and return a response."""
    enforce_chat_rate_limit(request)
    session = session_store.get(request.state.session_id)
    conversation_history = session["history"]
    session_stats = session["stats"]

    user_text = body.message.strip()

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
    initial_verdict = verdict
    initial_score = risk_score

    logger.info(
        "Message checked | session=%s intent=%s action=%s verdict=%s score=%s",
        request.state.session_id[:8],
        intent,
        action,
        verdict,
        risk_score,
    )

    record_session_detection(session_stats, verdict, risk_score)

    if _should_block_message(detection, action, verdict):
        _append_panel_log(
            user_text,
            _detection_payload(detection),
            processed_at,
            session_scope=request.state.session_id,
        )
        return ChatResponse(
            reply=_blocked_reply(detection, verdict, risk_score),
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

    conversation_history.append({"role": "user", "content": user_text})
    session["history"] = _trim_history(conversation_history)

    reply = llm_client.get_response(session["history"])
    session["history"].append({"role": "assistant", "content": reply})

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
        revise_session_detection(
            session_stats,
            initial_verdict,
            initial_score,
            verdict,
            risk_score,
        )
        logger.warning(
            "DETECTOR/RESPONSE MISMATCH | session=%s text=%r escalated to %s",
            request.state.session_id[:8],
            user_text[:80],
            risk_score,
        )

    final_detection = _detection_payload(
        {
            "verdict": verdict,
            "risk_score": risk_score,
            "matched_patterns": matched_patterns,
            "matched_categories": matched_categories,
            "category_details": category_details,
            "scoring_breakdown": scoring_breakdown,
            "injection_probability": injection_probability,
        }
    )
    _append_panel_log(
        user_text,
        final_detection,
        processed_at,
        session_scope=request.state.session_id,
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
async def clear(request: Request):
    """Reset conversation history and session-scoped stats/log for the current session."""
    session_id = request.state.session_id
    session_store.reset(session_id)
    global _panel_log
    _panel_log = [item for item in _panel_log if item.get("session_scope") == "feed"]
    logger.info("Conversation history cleared for session %s", session_id[:8])
    return {"status": "cleared"}


# ── Static files ───────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))

app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🛡️  AI Chatbot Web Interface")
    print("─" * 40)
    print("Chat UI  →  http://localhost:3000")
    print("Detector →  http://localhost:8000")
    print("─" * 40 + "\n")
    uvicorn.run("web_server:app", host="0.0.0.0", port=3000, reload=True)
