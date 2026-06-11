"""Phase 2 — Intent classification before threat detection."""

from __future__ import annotations

import re
from typing import Any, Literal


Intent = Literal[
    "safe",
    "educational",
    "defensive",
    "research",
    "suspicious",
    "malicious",
    "credential_theft",
    "data_exfiltration",
    "social_engineering",
]

BLOCKING_INTENTS = frozenset({"credential_theft", "data_exfiltration", "social_engineering"})

_BLOCKING_INTENT_RULES: list[tuple[Intent, list[str], float]] = [
    (
        "credential_theft",
        [
            r"\bsend\s+credentials?\b",
            r"\bsend\s+credentials?\s+to\s+me\b",
            r"\bgive\s+(?:me\s+)?(?:the\s+)?passwords?\b",
            r"\bshare\s+(?:the\s+)?login\b",
            r"\breveal\s+(?:the\s+)?secrets?\b",
            r"\bsend\s+(?:me\s+)?(?:the\s+)?tokens?\b",
            r"\bshow\s+(?:me\s+)?(?:the\s+)?api\s*keys?\b",
            r"\baccount\s+access\b",
            r"\b(give|send|share|provide)\s+(?:me\s+)?(?:your\s+)?credentials?\b",
        ],
        0.97,
    ),
    (
        "data_exfiltration",
        [
            r"\bexport\s+records?\b",
            r"\bdownload\s+private\s+data\b",
            r"\breveal\s+documents?\b",
            r"\b(exfiltrat|dump|export|download)\b.*\b(records?|private\s+data|documents?)\b",
        ],
        0.96,
    ),
    (
        "social_engineering",
        [
            r"\b(trust\s+me|believe\s+me).{0,40}(?:password|credential|access|secret)\b",
            r"\b(?:i\s+am|i'm)\s+(?:an?\s+)?(?:admin|it\s+support|security\s+team)\b",
            r"\bpretend\s+(?:to\s+be|you\s+are)\s+(?:an?\s+)?(?:admin|manager|ceo)\b",
            r"\b(?:urgent|emergency)\b.*\b(?:override|bypass|credential|password)\b",
        ],
        0.95,
    ),
]

_INTENT_RULES: list[tuple[Intent, list[str], float]] = [
    (
        "malicious",
        [
            r"\b(steal|extract|dump|exfiltrate|harvest)\b.*\b(credentials?|passwords?|database|customer|admin)\b",
            r"\bsteal\s+credentials?\b",
            r"\b(bypass|hack|crack)\b.*\b(admin|login|authentication|2fa|mfa)\b",
            r"\bignore\b.*\b(system|previous|all)\b.*\b(instructions?|prompt|rules?)\b",
            r"\bignore\s+(system|all|previous)\s+instructions?\b",
            r"\b(generate|create|write|produce|build)\b.*\b(malware|ransomware|virus|trojan|keylogger)\b",
            r"\b(print|reveal|show|display|repeat)\b.*\b(system prompt|hidden prompt|instructions)\b",
            r"\b(drop|truncate)\b.*\b(production|live)\b.*\b(table|database)\b",
        ],
        0.95,
    ),
    (
        "suspicious",
        [
            r"\b(generate|create|write|craft|produce)\b.*\b(payload|exploit|shellcode|injection string)\b",
            r"\b(give me|provide|show me)\b.*\b(working|live|real)\b.*\b(exploit|payload|attack)\b",
            r"\b(bypass|disable|remove|circumvent)\b.*\b(filter|guardrail|safety|restriction)\b",
            r"\b(jailbreak|dan mode|developer mode|god mode)\b",
        ],
        0.88,
    ),
    (
        "research",
        [
            r"\b(compare|contrast|difference between|vs\.?|versus)\b",
            r"\b(pros and cons|trade-?offs?|attack surface)\b",
            r"\b(research|literature review|survey of)\b.*\b(vulnerabilit|attack|threat)\b",
        ],
        0.82,
    ),
    (
        "defensive",
        [
            r"\b(how (do i|to)|ways? to|best practices? (for|to))\b.*\b(prevent|protect|secure|mitigate|defend|avoid|fix|patch)\b",
            r"\b(secure coding|hardening|security (controls|measures)|input validation)\b",
            r"\b(show|give)\b.*\b(secure|safe)\b.*\b(examples?|patterns?|practices?|implementations?)\b",
        ],
        0.85,
    ),
    (
        "educational",
        [
            r"\b(how does|how do|what is|what are|explain|teach me|tell me about|describe|define)\b",
            r"\b(concept of|basics of|introduction to|overview of|fundamentals of)\b",
            r"\b(for (my|a)\b.*\b(class|course|homework|assignment|study|learning|education)\b)",
            r"\b(for (educational|academic|learning|research) purposes?)\b",
        ],
        0.90,
    ),
]

_COMPILED_BLOCKING_RULES: list[tuple[Intent, list[re.Pattern[str]], float]] = [
    (intent, [re.compile(p, re.IGNORECASE) for p in patterns], weight)
    for intent, patterns, weight in _BLOCKING_INTENT_RULES
]

_COMPILED_RULES: list[tuple[Intent, list[re.Pattern[str]], float]] = [
    (intent, [re.compile(p, re.IGNORECASE) for p in patterns], weight)
    for intent, patterns, weight in _INTENT_RULES
]


def _score_rules(
    text: str,
    rules: list[tuple[Intent, list[re.Pattern[str]], float]],
) -> dict[Intent, float]:
    scores: dict[Intent, float] = {}
    for intent, patterns, weight in rules:
        hits = 0
        for pattern in patterns:
            try:
                if pattern.search(text):
                    hits += 1
            except Exception:
                continue
        if hits:
            scores[intent] = min(0.99, weight + min(hits - 1, 2) * 0.03)
    return scores


def classify_intent(text: str) -> dict[str, Any]:
    """
    Classify user intent using ordered rule patterns.

    Returns:
        Dict with intent and confidence (0.0–1.0).
    """
    if not text or not text.strip():
        return {"intent": "safe", "confidence": 0.99}

    blocking_scores = _score_rules(text, _COMPILED_BLOCKING_RULES)
    if blocking_scores:
        best_blocking = max(blocking_scores, key=lambda key: blocking_scores[key])
        return {
            "intent": best_blocking,
            "confidence": round(blocking_scores[best_blocking], 2),
        }

    scores: dict[Intent, float] = {
        "safe": 0.35,
        "educational": 0.0,
        "defensive": 0.0,
        "research": 0.0,
        "suspicious": 0.0,
        "malicious": 0.0,
        "credential_theft": 0.0,
        "data_exfiltration": 0.0,
        "social_engineering": 0.0,
    }

    for intent, patterns, weight in _COMPILED_RULES:
        hits = 0
        for pattern in patterns:
            try:
                if pattern.search(text):
                    hits += 1
            except Exception:
                continue
        if hits:
            scores[intent] = min(0.99, weight + min(hits - 1, 2) * 0.03)

    if scores["defensive"] >= 0.80 and scores["educational"] >= 0.80:
        scores["educational"] *= 0.5
    if scores["research"] >= 0.80 and scores["educational"] >= 0.80:
        scores["educational"] *= 0.6

    if scores["educational"] >= 0.85 and scores["suspicious"] < 0.92:
        scores["suspicious"] *= 0.35
    if scores["defensive"] >= 0.85 and scores["suspicious"] < 0.92:
        scores["suspicious"] *= 0.4
    if scores["research"] >= 0.80 and scores["suspicious"] < 0.92:
        scores["suspicious"] *= 0.5

    best_intent: Intent = max(scores, key=lambda key: scores[key])
    confidence = round(scores[best_intent], 2)

    if best_intent == "safe" and confidence <= 0.40:
        confidence = 0.75

    return {"intent": best_intent, "confidence": confidence}
