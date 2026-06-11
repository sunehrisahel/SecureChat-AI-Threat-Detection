"""Risk scoring engine combining regex categories and ML signals."""

from __future__ import annotations

from typing import Literal

from app.detector import HIGH_SEVERITY_CATEGORIES


Verdict = Literal["safe", "suspicious", "high_risk", "blocked"]


def _has_high_severity(matched_categories: list[str]) -> bool:
    return any(category in HIGH_SEVERITY_CATEGORIES for category in matched_categories)


def calculate_score(
    regex_matched: bool,
    regex_patterns_count: int,
    matched_categories: list[str],
    highest_category_score: int,
    injection_probability: float,
    safe_context_count: int = 0,
    text: str = "",
) -> dict:
    """
    Compute a category-aware composite risk score and verdict.

    Returns:
        Dict with risk_score, verdict, and scoring_breakdown.
    """
    del regex_matched, text  # retained for API compatibility

    if injection_probability >= 0.6 and safe_context_count == 0:
        ml_component = injection_probability * 40
    elif injection_probability >= 0.6 and safe_context_count >= 1:
        ml_component = injection_probability * 15
    elif injection_probability >= 0.45:
        ml_component = injection_probability * 20
    else:
        ml_component = 0.0

    category_component = highest_category_score if matched_categories else 0
    pattern_bonus = (
        min((regex_patterns_count - 1) * 5, 15) if regex_patterns_count > 0 else 0
    )
    multi_bonus = (
        min((len(matched_categories) - 1) * 5, 20) if len(matched_categories) > 1 else 0
    )

    raw_score = int(ml_component + category_component + pattern_bonus + multi_bonus)

    if not _has_high_severity(matched_categories):
        if safe_context_count >= 2:
            raw_score = int(raw_score * 0.3)
        elif safe_context_count >= 1:
            raw_score = int(raw_score * 0.5)

    final_score = min(raw_score, 100)

    if final_score >= 90:
        verdict: Verdict = "blocked"
    elif final_score >= 60:
        verdict = "high_risk"
    elif final_score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "scoring_breakdown": {
            "ml_component": round(ml_component, 1),
            "category_component": category_component,
            "pattern_bonus": pattern_bonus,
            "multi_category_bonus": multi_bonus,
            "safe_context_discount": safe_context_count,
        },
    }


def compute_risk_score(
    regex_matched: bool,
    regex_patterns_count: int,
    injection_probability: float,
    matched_categories: list[str] | None = None,
    highest_category_score: int = 0,
    safe_context_count: int = 0,
    text: str = "",
) -> tuple[int, Verdict]:
    """Backward-compatible wrapper around calculate_score."""
    result = calculate_score(
        regex_matched=regex_matched,
        regex_patterns_count=regex_patterns_count,
        matched_categories=matched_categories or [],
        highest_category_score=highest_category_score,
        injection_probability=injection_probability,
        safe_context_count=safe_context_count,
        text=text,
    )
    return result["risk_score"], result["verdict"]
