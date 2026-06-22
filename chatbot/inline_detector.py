"""Run the prompt-injection detector in-process (same Vercel deployment as SecureChat)."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_BOOTSTRAPPED = False
_AVAILABLE = False


def _detector_roots() -> list[Path]:
    here = Path(__file__).resolve().parent
    return [
        here / "bundled_detector",
        here.parent / "prompt-injection-detector",
    ]


def bootstrap() -> bool:
    """Add detector package root to sys.path if present."""
    global _BOOTSTRAPPED, _AVAILABLE
    if _BOOTSTRAPPED:
        return _AVAILABLE
    _BOOTSTRAPPED = True
    for root in _detector_roots():
        if (root / "app" / "pipeline.py").exists():
            root_str = str(root)
            if root_str not in sys.path:
                sys.path.insert(0, root_str)
            try:
                from app.pipeline import analyze_text  # noqa: F401
            except Exception as exc:
                logger.warning("Inline detector import failed from %s: %s", root, exc)
                continue
            _AVAILABLE = True
            logger.info("Inline detector ready from %s", root)
            return True
    return False


def is_available() -> bool:
    return bootstrap()


def should_use_inline() -> bool:
    """Use in-process detector only for local dev (never on Vercel — bundle too heavy)."""
    mode = os.getenv("INLINE_DETECTOR", "auto").strip().lower()
    if mode in {"0", "false", "no", "off"}:
        return False
    if os.getenv("VERCEL"):
        return False
    if mode in {"1", "true", "yes", "on"}:
        return is_available()
    url = os.getenv("DETECTOR_URL", "")
    if is_available() and (
        not url.strip()
        or "127.0.0.1" in url
        or "localhost" in url
    ):
        return True
    return False


def analyze(text: str, source: str = "chatbot", assistant_refused: bool = False) -> dict:
    if not is_available():
        raise RuntimeError("Inline detector is not available")
    from app.pipeline import analyze_text

    return analyze_text(text, source=source, assistant_refused=assistant_refused)
