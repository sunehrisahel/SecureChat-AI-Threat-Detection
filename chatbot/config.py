"""Configuration for the chatbot and its external services."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

DETECTOR_URL = "http://localhost:8000/analyze"
DETECTOR_TIMEOUT = 5  # seconds

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = "claude-haiku-4-5"
MAX_TOKENS = 1024

BLOCKED_VERDICTS = ["high_risk", "blocked"]

SYSTEM_PROMPT = "You are a helpful assistant."
MAX_HISTORY = 10  # number of messages to keep in conversation history
