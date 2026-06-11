"""Phase 3 — Threat analysis with intent-aware severity scaling."""

from __future__ import annotations

import re
from typing import Any, Literal

from app.detector import detect
from app.intent_classifier import Intent


ThreatCategory = Literal[
    "sql_injection",
    "xss",
    "prompt_injection",
    "credential_theft",
    "command_injection",
    "data_exfiltration",
    "social_engineering",
    "malware",
    "system_abuse",
]

INTENT_SEVERITY_MULTIPLIER: dict[Intent, float] = {
    "safe": 0.15,
    "educational": 0.2,
    "defensive": 0.3,
    "research": 0.5,
    "suspicious": 1.0,
    "malicious": 1.3,
    "credential_theft": 1.0,
    "data_exfiltration": 1.0,
    "social_engineering": 1.0,
}

_LEGACY_CATEGORY_BASE: dict[str, int] = {
    "prompt_injection": 40,
    "jailbreak": 45,
    "data_exfiltration": 50,
    "social_engineering": 35,
    "harmful_content": 55,
    "system_abuse": 40,
    "identity_manipulation": 35,
    "obfuscation_evasion": 45,
    "malicious_code": 60,
    "privacy_violation": 50,
    "radicalization": 60,
    "misinformation": 30,
}

_SUBCATEGORY_PATTERNS: dict[ThreatCategory, list[str]] = {
    "sql_injection": [
        r"\bsql\b.*\b(injection|inject|injection attack|injection work)\b",
        r"\bsqli\b",
        r"\bunion\s+select\b",
        r"\bselect\b.*\bfrom\b",
    ],
    "xss": [r"\bxss\b", r"\bcross.?site scripting\b", r"\b<script\b"],
    "prompt_injection": [
        r"\b(ignore|disregard|forget|override)\b.*\b(instructions?|prompt|rules?)\b",
        r"\bignore\s+(system|all|previous|your)\s+instructions?\b",
        r"\b(system prompt|jailbreak|dan\b)\b",
    ],
    "credential_theft": [
        r"\b(steal|extract|dump|harvest|retrieve)\b.*\b(credential|password|api.?key|token)\b",
        r"\badmin\b.*\b(password|credential|login)\b",
    ],
    "command_injection": [
        r"\b(command injection|shell injection|os injection)\b",
        r"\b(rce|remote code execution)\b",
        r"\|\s*(bash|sh|cmd)\b",
    ],
    "data_exfiltration": [
        r"\b(exfiltrat|dump|export|extract)\b.*\b(data|database|table|record)\b",
        r"\bcustomer\b.*\bdata\b",
    ],
    "social_engineering": [
        r"\b(social engineering|phishing|pretexting|impersonat)\b",
        r"\b(trust me|i am an? admin|authorized employee)\b",
    ],
    "malware": [
        r"\b(malware|ransomware|virus|trojan|keylogger|rootkit|botnet)\b",
        r"\b(write|create|generate)\b.*\b(exploit|payload|shellcode)\b",
    ],
    "system_abuse": [
        r"\b(ddos|resource exhaustion|token flood|spam)\b.*\b(api|server|system)\b",
        r"\b(reverse engineer|steal)\b.*\b(model|weights)\b",
    ],
}

_COMPILED_SUBCATEGORY = {
    category: [re.compile(p, re.IGNORECASE) for p in patterns]
    for category, patterns in _SUBCATEGORY_PATTERNS.items()
}


def _detect_subcategories(text: str) -> list[ThreatCategory]:
    found: list[ThreatCategory] = []
    for category, patterns in _COMPILED_SUBCATEGORY.items():
        for pattern in patterns:
            try:
                if pattern.search(text):
                    found.append(category)
                    break
            except Exception:
                continue
    return found


def _map_legacy_categories(legacy_categories: list[str]) -> list[ThreatCategory]:
    mapping: dict[str, list[ThreatCategory]] = {
        "prompt_injection": ["prompt_injection"],
        "jailbreak": ["prompt_injection"],
        "data_exfiltration": ["data_exfiltration", "sql_injection", "credential_theft"],
        "social_engineering": ["social_engineering", "credential_theft"],
        "harmful_content": ["malware"],
        "system_abuse": ["system_abuse"],
        "identity_manipulation": ["social_engineering"],
        "obfuscation_evasion": ["prompt_injection"],
        "malicious_code": ["malware", "sql_injection", "xss", "command_injection"],
        "privacy_violation": ["data_exfiltration"],
        "radicalization": ["malware"],
        "misinformation": ["social_engineering"],
    }
    categories: list[ThreatCategory] = []
    for legacy in legacy_categories:
        for mapped in mapping.get(legacy, []):
            if mapped not in categories:
                categories.append(mapped)
    return categories


def analyze_threats(text: str, intent: Intent) -> dict[str, Any]:
    """
    Run threat analysis on normalized text with intent-based severity scaling.

    Returns:
        detected, categories, severity (0-100), confidence (0-1), and legacy details.
    """
    legacy = detect(text)
    categories = _detect_subcategories(text)
    for mapped in _map_legacy_categories(legacy.get("matched_categories", [])):
        if mapped not in categories:
            categories.append(mapped)

    detected = bool(categories) or legacy.get("matched", False)

    base_severity = 0
    if legacy.get("matched_categories"):
        base_severity = max(
            _LEGACY_CATEGORY_BASE.get(cat, 30)
            for cat in legacy["matched_categories"]
        )
    elif categories:
        base_severity = 35

    pattern_count = len(legacy.get("matched_patterns", []))
    pattern_boost = min(pattern_count * 3, 15)
    raw_severity = min(base_severity + pattern_boost, 100)

    multiplier = INTENT_SEVERITY_MULTIPLIER.get(intent, 1.0)
    severity = int(min(raw_severity * multiplier, 100))

    if detected:
        confidence = min(
            0.98,
            0.45 + (pattern_count * 0.06) + (len(categories) * 0.08) + (base_severity / 200),
        )
    else:
        confidence = 0.05

    return {
        "detected": detected,
        "categories": categories,
        "severity": severity,
        "confidence": round(confidence, 2),
        "legacy": legacy,
        "raw_severity": raw_severity,
        "severity_multiplier": multiplier,
    }
