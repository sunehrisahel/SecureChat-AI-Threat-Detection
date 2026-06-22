"""FastAPI application for AI threat analysis."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(_PROJECT_ROOT / ".env")
load_dotenv(_PROJECT_ROOT / "prompt-injection-detector" / ".env", override=False)

from app.analytics import compute_analytics
from app.classifier import get_model_warning, load_model
from app.models import (
    AnalyticsResponse,
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
    SuggestFixRequest,
    SuggestFixResponse,
)
from app.paths import detections_log_path
from app.pipeline import analyze_text
from app.security import (
    enforce_analyze_rate_limit,
    require_admin_key,
    require_detector_key,
    require_red_team_key,
)
from app.suggest_fix import build_suggest_fix

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

MAX_LOG_ENTRIES = 100

_default_origins = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8502,http://127.0.0.1:8502"
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in __import__("os").getenv("ALLOWED_ORIGINS", _default_origins).split(",")
    if origin.strip()
]


def _ensure_logs_file() -> None:
    log_path = detections_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if not log_path.exists():
        log_path.touch()
        logger.info("Created detections log at %s", log_path)


def _append_detection(entry: dict[str, Any]) -> None:
    _ensure_logs_file()
    log_path = detections_log_path()
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _read_recent_logs(limit: int = MAX_LOG_ENTRIES) -> list[dict[str, Any]]:
    _ensure_logs_file()
    log_path = detections_log_path()
    entries: list[dict[str, Any]] = []

    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("Skipping malformed log line: %s", line[:80])

    return entries[-limit:]


@asynccontextmanager
async def lifespan(app: FastAPI):
    _ensure_logs_file()
    if not __import__("os").getenv("SKIP_STARTUP_MODEL_LOAD"):
        loaded = load_model()
        if loaded:
            logger.info("ML classifier ready")
        else:
            warning = get_model_warning()
            logger.warning("ML classifier unavailable: %s", warning)
    else:
        logger.info("Deferring ML model load until first /analyze request")
    yield


app = FastAPI(
    title="AI Threat Detection API",
    description="Intent-aware security middleware for AI chat applications",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    request: Request,
    body: AnalyzeRequest,
    _: None = Depends(require_detector_key),
) -> AnalyzeResponse:
    enforce_analyze_rate_limit(request)
    result = analyze_text(
        body.text,
        source=body.source,
        assistant_refused=body.assistant_refused,
    )

    log_entry = {
        **result["observability"],
        "text": result["text"],
        "verdict": result["verdict"],
        "action": result["action"],
        "matched_categories": result["matched_categories"],
        "matched_patterns": result["matched_patterns"],
        "scoring_breakdown": result["scoring_breakdown"],
        "mismatch_alert": result.get("mismatch_alert"),
    }
    _append_detection(log_entry)

    logger.info(
        "Analyzed request from %s: intent=%s action=%s risk=%d categories=%s",
        body.source,
        result["intent"],
        result["action"],
        result["risk_score"],
        result["threat_categories"],
    )

    return AnalyzeResponse(**result)


@app.post("/suggest-fix", response_model=SuggestFixResponse)
async def suggest_fix(
    body: SuggestFixRequest,
    _: None = Depends(require_red_team_key),
) -> SuggestFixResponse:
    """Suggest detector improvements for attacks that evaded classification."""
    return build_suggest_fix(body)


@app.get("/logs")
async def get_logs(_: None = Depends(require_admin_key)) -> list[dict[str, Any]]:
    return _read_recent_logs(MAX_LOG_ENTRIES)


@app.get("/analytics", response_model=AnalyticsResponse)
async def analytics(_: None = Depends(require_admin_key)) -> AnalyticsResponse:
    data = compute_analytics()
    return AnalyticsResponse(**data)
