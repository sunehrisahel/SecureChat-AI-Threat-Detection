"""Configuration for the chatbot and its external services."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

DETECTOR_URL = os.getenv("DETECTOR_URL", "").strip()
if not DETECTOR_URL:
    if os.getenv("VERCEL"):
        DETECTOR_URL = "https://securechat-detector-api.onrender.com/analyze"
    else:
        DETECTOR_URL = "http://localhost:8000/analyze"
DETECTOR_TIMEOUT = int(os.getenv("DETECTOR_TIMEOUT", "10"))
DETECTOR_API_KEY = os.getenv("DETECTOR_API_KEY", "")
DETECTOR_FAIL_OPEN = os.getenv("DETECTOR_FAIL_OPEN", "false").lower() in {"1", "true", "yes"}
# Bypass Vercel Deployment Protection on the detector project (server-to-server calls).
VERCEL_PROTECTION_BYPASS = os.getenv("VERCEL_PROTECTION_BYPASS", "").strip()

# Production-style defaults: block warn-tier threats unless explicitly disabled.
BLOCK_WARN_ACTION = os.getenv("BLOCK_WARN_ACTION", "true").lower() in {"1", "true", "yes"}

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
RED_TEAM_API_KEY = os.getenv("RED_TEAM_API_KEY", "")
RATE_LIMIT_CHAT = int(os.getenv("RATE_LIMIT_CHAT", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

_default_origins = "http://localhost:3000,http://127.0.0.1:3000"
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", _default_origins).split(",")
    if origin.strip()
]
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}


def detector_health_url() -> str:
    """Derive the detector health URL from DETECTOR_URL."""
    if DETECTOR_URL.endswith("/analyze"):
        return DETECTOR_URL[: -len("/analyze")] + "/health"
    return DETECTOR_URL.rstrip("/") + "/health"


def detector_logs_url() -> str:
    """Derive the detector logs URL from DETECTOR_URL."""
    if DETECTOR_URL.endswith("/analyze"):
        return DETECTOR_URL[: -len("/analyze")] + "/logs"
    return DETECTOR_URL.rstrip("/") + "/logs"


ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = "claude-haiku-4-5"
MAX_TOKENS = 1024

BLOCKED_VERDICTS = ["high_risk", "blocked"]

SYSTEM_PROMPT = "You are a helpful assistant."
MAX_HISTORY = 10  # number of messages to keep in conversation history
