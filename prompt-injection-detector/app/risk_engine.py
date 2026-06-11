"""Phase 4 — Composite risk scoring engine."""

from __future__ import annotations

from typing import Any, Literal

from app.intent_classifier import BLOCKING_INTENTS, Intent


Verdict = Literal["safe", "suspicious", "high_risk", "blocked"]
Action = Literal["allow", "warn", "block"]

INTENT_RISK_SCORES: dict[Intent, int] = {
    "safe": 5,
    "educational": 10,
    "defensive": 15,
    "research": 25,
    "suspicious": 70,
    "malicious": 95,
    "credential_theft": 98,
    "data_exfiltration": 95,
    "social_engineering": 92,
}

BLOCK_INTENTS = frozenset({"suspicious", "malicious", *BLOCKING_INTENTS})
THREAT_CONFIDENCE_BLOCK_THRESHOLD = 0.6


def _confidence_penalty(intent: Intent, intent_confidence: float, threat: dict[str, Any]) -> float:
    """Penalty for uncertainty or intent/threat disagreement."""
    if not threat.get("detected"):
        return (1 - intent_confidence) * 10

    benign_intents = {"safe", "educational", "defensive", "research"}
    if intent in benign_intents:
        # Keyword hits under benign intent should not dominate scoring.
        return threat.get("confidence", 0.0) * 12

    return (1 - intent_confidence) * 25


def calculate_risk(
    intent: Intent,
    intent_confidence: float,
    threat: dict[str, Any],
) -> dict[str, Any]:
    """
    Compute composite risk score and verdict.

    Formula:
        risk = 0.4 * intent_score + 0.4 * threat_score + 0.2 * confidence_penalty
    """
    intent_score = INTENT_RISK_SCORES.get(intent, 10)
    threat_score = threat.get("severity", 0)
    penalty = _confidence_penalty(intent, intent_confidence, threat)

    raw_risk = 0.4 * intent_score + 0.4 * threat_score + 0.2 * penalty
    risk_score = int(min(max(raw_risk, 0), 100))

    threat_confidence = threat.get("confidence", 0.0)
    threat_detected = threat.get("detected", False)
    can_block = intent in BLOCK_INTENTS and threat_confidence > THREAT_CONFIDENCE_BLOCK_THRESHOLD

    if intent == "malicious" and intent_confidence >= 0.9 and threat_detected:
        threat_confidence = max(threat_confidence, 0.75)
        can_block = True

    if intent in BLOCKING_INTENTS:
        risk_score = max(risk_score, 80)
        can_block = True
        threat_confidence = max(threat_confidence, 0.85)
    elif can_block and threat_detected and intent == "malicious":
        risk_score = max(risk_score, 65)
    elif can_block and threat_detected and intent == "suspicious":
        risk_score = max(risk_score, 45)

    if risk_score >= 61 and can_block:
        verdict: Verdict = "blocked" if risk_score >= 90 else "high_risk"
    elif risk_score >= 61 and intent in BLOCK_INTENTS:
        verdict = "high_risk"
    elif risk_score >= 31:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # Benign intents must never be blocked solely on keyword/threat overlap.
    if intent in {"safe", "educational", "defensive", "research"} and verdict in {"high_risk", "blocked"}:
        if threat_confidence <= THREAT_CONFIDENCE_BLOCK_THRESHOLD or not can_block:
            verdict = "suspicious" if risk_score >= 31 else "safe"
            risk_score = min(risk_score, 60 if verdict == "suspicious" else 30)

    if intent in {"safe", "educational", "defensive"} and intent not in BLOCKING_INTENTS and risk_score > 30:
        risk_score = min(risk_score, 30)
        verdict = "safe"

    if intent in BLOCKING_INTENTS:
        verdict = "blocked"
        risk_score = max(risk_score, 80)

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "scoring_breakdown": {
            "intent_score": intent_score,
            "threat_score": threat_score,
            "confidence_penalty": round(penalty, 1),
            "intent": intent,
            "intent_confidence": intent_confidence,
            "threat_confidence": threat_confidence,
            "can_block": can_block,
            "raw_risk": round(raw_risk, 1),
        },
    }
