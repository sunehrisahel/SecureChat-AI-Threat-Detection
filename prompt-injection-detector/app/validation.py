"""Detector/response consistency validation."""

from __future__ import annotations

RESPONSE_ESCALATION_FLOOR = 80
MISMATCH_RISK_THRESHOLD = 60


def apply_response_escalation(risk_score: int, assistant_refused: bool) -> int:
    """Escalate risk when the assistant refused but the detector scored low."""
    if assistant_refused:
        return max(risk_score, RESPONSE_ESCALATION_FLOOR)
    return risk_score


def validate_detector_response(risk_score: int, assistant_refused: bool) -> None:
    """
    Ensure detector risk aligns with assistant refusal.

    Raises:
        ValueError: If assistant refused but risk remains below threshold.
    """
    if assistant_refused and risk_score < MISMATCH_RISK_THRESHOLD:
        raise ValueError(
            f"Detector/response mismatch: assistant_refused=True but risk_score={risk_score}"
        )
