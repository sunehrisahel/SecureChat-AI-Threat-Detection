"""Phase 1 — Input normalization and obfuscation decoding."""

from __future__ import annotations

import base64
import re
import unicodedata
from typing import Any


_LEET_MAP = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
})

_SPACED_TOKEN = re.compile(r"\b([a-z])(?:\s+[a-z]){1,12}\b", re.IGNORECASE)
_BASE64_CANDIDATE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")


def _collapse_spaced_letters(text: str) -> str:
    """Collapse patterns like 's q l injection' into 'sql injection'."""

    def _replace(match: re.Match[str]) -> str:
        return match.group(0).replace(" ", "")

    previous = None
    current = text
    while previous != current:
        previous = current
        current = _SPACED_TOKEN.sub(_replace, current)
    return current


def _apply_leetspeak(text: str) -> str:
    return text.translate(_LEET_MAP)


def _decode_base64_segments(text: str) -> str:
    tokens = text.split()
    decoded_tokens: list[str] = []
    for token in tokens:
        if _BASE64_CANDIDATE.match(token):
            try:
                padding = "=" * (-len(token) % 4)
                decoded = base64.b64decode(token + padding).decode("utf-8", errors="ignore")
                if decoded and decoded.isprintable():
                    decoded_tokens.append(decoded)
                    continue
            except Exception:
                pass
        decoded_tokens.append(token)
    return " ".join(decoded_tokens)


def _normalize_homoglyphs(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def normalize_input(raw_input: str) -> dict[str, Any]:
    """
    Normalize user input while preserving the original for auditing.

    Returns:
        Dict with raw_input, normalized_input, decoded_input, and obfuscation flags.
    """
    if raw_input is None:
        raw_input = ""
    if not isinstance(raw_input, str):
        try:
            raw_input = str(raw_input)
        except Exception:
            raw_input = ""

    raw = raw_input
    text = _normalize_homoglyphs(raw)
    text = text.lower()
    text = re.sub(r"\s+", " ", text).strip()

    decoded = _decode_base64_segments(text)
    decoded = _collapse_spaced_letters(decoded)
    decoded = _apply_leetspeak(decoded)
    decoded = re.sub(r"\s+", " ", decoded).strip()

    obfuscation_detected = decoded != text

    return {
        "raw_input": raw,
        "normalized_input": text,
        "decoded_input": decoded,
        "obfuscation_detected": obfuscation_detected,
    }
