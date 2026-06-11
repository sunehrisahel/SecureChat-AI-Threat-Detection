"""Detect assistant refusals in model responses."""

from __future__ import annotations

import re

_REFUSAL_PATTERNS = [
    r"\bi (?:can'?t|cannot|won'?t|am not able to)\b",
    r"\bi'?m (?:sorry|afraid|unable).{0,60}(?:can'?t|cannot|won'?t|unable)\b",
    r"\bunable to (?:help|assist|provide|comply|fulfill|share|give)\b",
    r"\bnot able to (?:help|assist|provide|comply|share|give)\b",
    r"\bi (?:must|have to) (?:decline|refuse)\b",
    r"\b(?:can'?t|cannot|won'?t) (?:help|assist|provide|share|give|comply)\b",
    r"\bagainst (?:my|safety) (?:guidelines|policies|rules)\b",
    r"\bnot (?:appropriate|permitted|allowed)\b",
    r"\bi don'?t (?:provide|share|give|disclose)\b",
]

_COMPILED_REFUSAL = [re.compile(p, re.IGNORECASE) for p in _REFUSAL_PATTERNS]


def is_assistant_refusal(reply: str) -> bool:
    """Return True if the assistant reply indicates a safety refusal."""
    if not reply or not reply.strip():
        return False
    if reply.strip().lower().startswith("error:"):
        return False
    return any(pattern.search(reply) for pattern in _COMPILED_REFUSAL)
