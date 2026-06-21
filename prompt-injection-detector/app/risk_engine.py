"""Phase 4 — Composite risk scoring engine."""

from __future__ import annotations

from typing import Any, Literal

from app.intent_classifier import BLOCKING_INTENTS, Intent


Verdict = Literal["safe", "suspicious", "high_risk", "blocked"]
Action = Literal["allow", "warn", "block"]

# Scales how much detection confidence maps to risk for each intent.
INTENT_CONFIDENCE_MULTIPLIER: dict[Intent, float] = {
    "safe": 0.1,
    "educational": 0.15,
    "defensive": 0.2,
    "research": 0.35,
    "suspicious": 0.6,
    "malicious": 1.0,
    "credential_theft": 1.0,
    "data_exfiltration": 0.95,
    "social_engineering": 0.9,
}

BLOCK_INTENTS = frozenset({"suspicious", "malicious", *BLOCKING_INTENTS})
THREAT_CONFIDENCE_BLOCK_THRESHOLD = 0.6
STRONG_DETECTION_THRESHOLD = 0.8


def calculate_risk(
    intent: Intent,
    intent_confidence: float,
    threat: dict[str, Any],
    injection_probability: float = 0.0,
) -> dict[str, Any]:
    """
    Compute a per-input risk score from live detector signals.

    Formula (continuous — no verdict-label lookup floors):
        detection_confidence = max(injection_probability, threat_confidence)
        effective_weight = intent multiplier, boosted when detection is strong
        base = detection_confidence * 100 * effective_weight
        raw_risk = base + severity_component + pattern_bonus
    """
    threat_confidence = float(threat.get("confidence", 0.0))
    severity = int(threat.get("severity", 0))
    raw_severity = float(threat.get("raw_severity", severity))
    legacy = threat.get("legacy") or {}
    pattern_count = len(legacy.get("matched_patterns", []))
    category_count = len(legacy.get("matched_categories", []))
    threat_detected = bool(threat.get("detected"))

    rule_confidence = threat_confidence if threat_detected else 0.0
    detection_confidence = max(float(injection_probability), rule_confidence)

    intent_mult = INTENT_CONFIDENCE_MULTIPLIER.get(intent, 0.5)
    effective_weight = intent_mult

    if intent in BLOCKING_INTENTS:
        detection_confidence = max(detection_confidence, intent_confidence)
        effective_weight = max(effective_weight, 0.95)

    legacy_cats = set(legacy.get("matched_categories") or [])
    threat_cats = set(threat.get("categories") or [])
    injection_like = bool(
        "prompt_injection" in threat_cats
        or legacy_cats
        & {"prompt_injection", "jailbreak", "obfuscation_evasion", "identity_manipulation"}
    )

    if threat_detected and detection_confidence >= STRONG_DETECTION_THRESHOLD:
        misclassified_benign = (
            intent in {"safe", "educational", "defensive", "research"}
            and intent_confidence < 0.85
        )
        if intent == "malicious":
            effective_weight = max(effective_weight, detection_confidence * 0.72)
        elif misclassified_benign and raw_severity >= 50 and injection_like:
            effective_weight = max(effective_weight, detection_confidence * 0.72)

    severity_component = min(raw_severity / 100.0 * 18.0, 18.0)
    pattern_bonus = min(pattern_count * 3.0 + max(category_count - 1, 0) * 2.0, 18.0)

    base = detection_confidence * 100.0 * effective_weight
    raw_risk = base + severity_component + pattern_bonus

    if intent in {"educational", "defensive", "research"} and intent_confidence >= 0.85:
        raw_risk *= 0.85

    risk_score = int(min(max(round(raw_risk), 0), 100))

    can_block = intent in BLOCK_INTENTS and threat_confidence > THREAT_CONFIDENCE_BLOCK_THRESHOLD
    threat_confidence_out = threat_confidence

    if intent in BLOCKING_INTENTS:
        can_block = True
        threat_confidence_out = max(threat_confidence, 0.85)
    elif intent == "malicious" and intent_confidence >= 0.9 and threat_detected:
        can_block = True
        threat_confidence_out = max(threat_confidence, 0.75)

    if intent in BLOCKING_INTENTS:
        verdict: Verdict = "blocked"
    elif risk_score >= 90 and can_block:
        verdict = "blocked"
    elif risk_score >= 61 and intent == "malicious" and can_block:
        verdict = "high_risk"
    elif risk_score >= 61 and intent in BLOCKING_INTENTS:
        verdict = "high_risk"
    elif risk_score >= 31:
        verdict = "suspicious"
    else:
        verdict = "safe"

    if intent in {"safe", "educational", "defensive", "research"} and verdict in {"high_risk", "blocked"}:
        if threat_confidence <= THREAT_CONFIDENCE_BLOCK_THRESHOLD or not can_block:
            verdict = "suspicious" if risk_score >= 31 else "safe"

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "scoring_breakdown": {
            "detection_confidence": round(detection_confidence, 3),
            "injection_probability": round(float(injection_probability), 3),
            "threat_confidence": round(threat_confidence, 3),
            "intent_multiplier": intent_mult,
            "effective_weight": round(effective_weight, 3),
            "severity_component": round(severity_component, 1),
            "pattern_bonus": round(pattern_bonus, 1),
            "raw_severity": raw_severity,
            "intent": intent,
            "intent_confidence": intent_confidence,
            "threat_confidence_out": threat_confidence_out,
            "can_block": can_block,
            "raw_risk": round(raw_risk, 1),
        },
    }
