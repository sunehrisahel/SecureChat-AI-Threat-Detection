"""Configuration for the chatbot and its external services."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

DETECTOR_URL = os.getenv("DETECTOR_URL", "http://localhost:8000/analyze")
DETECTOR_TIMEOUT = 5  # seconds


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
