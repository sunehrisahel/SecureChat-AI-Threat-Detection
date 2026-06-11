"""Pydantic request/response schemas for the analysis API."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, description="User-submitted text to analyze")
    source: str = Field(default="api-client", description="Origin of the request")
    assistant_refused: bool = Field(
        default=False,
        description="Set when the assistant refused; triggers response-aware escalation",
    )


class AnalyzeResponse(BaseModel):
    text: str
    verdict: Literal["safe", "suspicious", "high_risk", "blocked"]
    risk_score: int = Field(..., ge=0, le=100)
    action: Literal["allow", "warn", "block"]
    intent: str
    intent_confidence: float = Field(..., ge=0.0, le=1.0)
    injection_probability: float = Field(..., ge=0.0, le=1.0)
    regex_matched: bool
    matched_patterns: list[str]
    matched_categories: list[str]
    threat_categories: list[str]
    threat_detected: bool
    severity: int = Field(..., ge=0, le=100)
    threat_confidence: float = Field(..., ge=0.0, le=1.0)
    category_details: dict[str, Any]
    scoring_breakdown: dict[str, Any]
    safe_context_count: int = Field(..., ge=0)
    normalization: dict[str, Any]
    policy: dict[str, Any]
    observability: dict[str, Any]
    assistant_refused: bool = False
    detector_response_mismatch: bool = False
    mismatch_alert: Optional[str] = None
    timestamp: str
    source: str


class HealthResponse(BaseModel):
    status: str


class AnalyticsResponse(BaseModel):
    total_requests: int
    false_positive_rate: float
    false_negative_rate: float
    intent_distribution: dict[str, int]
    action_distribution: dict[str, int] = {}
    block_rate: float
    warn_rate: float
    allow_rate: float
