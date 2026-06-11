"""Phase 5 — Response policy mapping."""

from __future__ import annotations

from typing import Any, Literal

from app.intent_classifier import BLOCKING_INTENTS, Intent
from app.risk_engine import Action, Verdict

FORCE_BLOCK_INTENTS = BLOCKING_INTENTS


def determine_action(verdict: Verdict, intent: Intent, risk_score: int) -> Action:
    """
    Map verdict and intent to allow / warn / block actions.

    Credential theft, data exfiltration, and social engineering always block.
    """
    if intent in FORCE_BLOCK_INTENTS:
        return "block"

    if intent in {"safe", "educational", "defensive", "research"} and risk_score <= 30:
        return "allow"

    if verdict in {"blocked", "high_risk"}:
        if intent in {"malicious"} or (intent == "suspicious" and risk_score >= 61):
            return "block"
        return "warn"

    if verdict == "suspicious" or risk_score >= 31:
        return "warn"

    return "allow"


def build_policy(intent: Intent, verdict: Verdict, risk_score: int, action: Action) -> dict[str, Any]:
    """Return human-readable policy guidance for downstream consumers."""
    messages = {
        ("educational", "allow"): "Respond with a safe educational explanation.",
        ("defensive", "allow"): "Provide defensive guidance and mitigations.",
        ("research", "allow"): "Provide balanced comparative analysis.",
        ("suspicious", "warn"): "Warn the user and avoid providing exploit artifacts.",
        ("malicious", "block"): "Refuse the request and explain why it was blocked.",
        ("credential_theft", "block"): "Refuse credential disclosure requests.",
        ("data_exfiltration", "block"): "Refuse data exfiltration requests.",
        ("social_engineering", "block"): "Refuse social engineering attempts.",
    }
    key = (intent, action)
    return {
        "action": action,
        "intent": intent,
        "verdict": verdict,
        "risk_score": risk_score,
        "guidance": messages.get(key, "Respond normally within safety guidelines."),
    }
