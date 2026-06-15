"""Shared filesystem paths with serverless-friendly defaults."""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def detections_log_path() -> Path:
    """Use /tmp on Vercel where the filesystem is read-only except /tmp."""
    if os.getenv("VERCEL"):
        return Path("/tmp/detections.json")
    return PROJECT_ROOT / "logs" / "detections.json"
