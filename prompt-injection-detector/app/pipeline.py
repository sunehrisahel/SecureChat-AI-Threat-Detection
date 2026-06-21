"""End-to-end threat analysis pipeline orchestrating all phases."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.classifier import predict
from app.intent_classifier import BLOCKING_INTENTS, classify_intent
from app.normalizer import normalize_input
from app.policy import build_policy, determine_action
from app.risk_engine import calculate_risk
from app.threat_analyzer import analyze_threats
from app.validation import apply_response_escalation, validate_detector_response


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def analyze_text(
    text: str,
    source: str = "api-client",
    assistant_refused: bool = False,
) -> dict[str, Any]:
    """
    Run the full analysis pipeline on user text.

    Phases:
        1. Input normalization
        2. Intent classification
        3. Threat analysis (intent-aware)
        4. Risk scoring
        5. Response policy
        6. Response-aware escalation (optional)
    """
    normalization = normalize_input(text)
    analysis_text = normalization["decoded_input"] or normalization["normalized_input"]

    intent_result = classify_intent(analysis_text)
    intent = intent_result["intent"]
    intent_confidence = intent_result["confidence"]

    ml_result = predict(analysis_text)
    injection_probability = float(ml_result["injection_probability"])

    threat = analyze_threats(analysis_text, intent)
    risk = calculate_risk(intent, intent_confidence, threat, injection_probability)
    action = determine_action(risk["verdict"], intent, risk["risk_score"])

    pre_escalation_risk = risk["risk_score"]
    detector_response_mismatch = False

    if assistant_refused and pre_escalation_risk < 60:
        detector_response_mismatch = True

    if assistant_refused:
        risk["risk_score"] = apply_response_escalation(risk["risk_score"], True)
        risk["verdict"] = "blocked" if risk["risk_score"] >= 61 else "high_risk"
        action = "block"
        risk["scoring_breakdown"]["response_escalation"] = True
        risk["scoring_breakdown"]["pre_escalation_risk"] = pre_escalation_risk
        validate_detector_response(risk["risk_score"], assistant_refused=True)

    policy = build_policy(intent, risk["verdict"], risk["risk_score"], action)

    legacy = threat["legacy"]

    legacy_verdict = risk["verdict"]
    if action == "allow" and legacy_verdict != "safe" and intent not in BLOCKING_INTENTS:
        legacy_verdict = "safe"
    elif action == "warn" and legacy_verdict == "blocked":
        legacy_verdict = "suspicious"
    elif action == "block":
        legacy_verdict = "blocked" if risk["risk_score"] >= 90 else "high_risk"

    observability = {
        "timestamp": _utc_now_iso(),
        "raw_input": normalization["raw_input"],
        "normalized_input": normalization["normalized_input"],
        "decoded_input": normalization["decoded_input"],
        "obfuscation_detected": normalization["obfuscation_detected"],
        "intent": intent,
        "intent_confidence": intent_confidence,
        "threat_categories": threat["categories"],
        "threat_detected": threat["detected"],
        "severity": threat["severity"],
        "threat_confidence": threat["confidence"],
        "risk_score": risk["risk_score"],
        "final_action": action,
        "assistant_refused": assistant_refused,
        "detector_response_mismatch": detector_response_mismatch,
        "source": source,
    }

    return {
        "text": text,
        "verdict": legacy_verdict,
        "risk_score": risk["risk_score"],
        "action": action,
        "intent": intent,
        "intent_confidence": intent_confidence,
        "injection_probability": injection_probability,
        "regex_matched": legacy.get("matched", False),
        "matched_patterns": legacy.get("matched_patterns", []),
        "matched_categories": legacy.get("matched_categories", []),
        "category_details": legacy.get("category_details", {}),
        "threat_categories": threat["categories"],
        "threat_detected": threat["detected"],
        "severity": threat["severity"],
        "threat_confidence": threat["confidence"],
        "safe_context_count": legacy.get("safe_context_count", 0),
        "normalization": normalization,
        "scoring_breakdown": risk["scoring_breakdown"],
        "policy": policy,
        "observability": observability,
        "assistant_refused": assistant_refused,
        "detector_response_mismatch": detector_response_mismatch,
        "mismatch_alert": (
            "DETECTOR/RESPONSE MISMATCH" if detector_response_mismatch else None
        ),
        "timestamp": observability["timestamp"],
        "source": source,
    }
