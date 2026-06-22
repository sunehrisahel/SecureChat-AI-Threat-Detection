"""Battle mode plans and configuration helpers."""

from __future__ import annotations

CATEGORY_TO_TECHNIQUE: dict[str, str] = {
    "PROMPT_INJECTION": "direct_override",
    "CONTEXT_WRAPPING": "context_dilution",
    "HOMOGLYPH_SUBSTITUTION": "leetspeak_obfuscation",
    "CSV_EXFILTRATION": "csv_exfiltration",
    "ROLE_WRAPPING": "role_manipulation",
    "ZERO_WIDTH_INJECTION": "zero_width_injection",
    "DIRECT_OVERRIDE": "direct_override",
    "SOCIAL_ENGINEERING": "social_engineering",
}

QUICK_TECHNIQUES = [
    "direct_override",
    "leetspeak_obfuscation",
    "context_dilution",
    "zero_width_injection",
    "csv_exfiltration",
]

BATTLE_MODE_LABELS = {
    "quick": "Quick Test",
    "full": "Full Test",
    "custom": "Custom Test",
    "standard": "Standard Test",
}


def build_quick_battle_config() -> dict:
    return {
        "mode": "quick",
        "mode_label": "Quick Test",
        "techniques": list(QUICK_TECHNIQUES),
        "total_rounds": 5,
        "delay_sec": 0.5,
    }


def build_full_battle_config() -> dict:
    bank = [
        "direct_override",
        "context_dilution",
        "leetspeak_obfuscation",
        "csv_exfiltration",
        "role_manipulation",
        "zero_width_injection",
        "social_engineering",
    ]
    techniques = [bank[i % len(bank)] for i in range(15)]
    return {
        "mode": "full",
        "mode_label": "Full Test",
        "techniques": techniques,
        "total_rounds": 15,
        "delay_sec": 0.5,
    }


def build_custom_battle_config(
    selected_categories: list[str],
    variants: int,
    delay_ms: int,
) -> dict:
    techniques: list[str] = []
    for category in selected_categories:
        technique = CATEGORY_TO_TECHNIQUE.get(category, "direct_override")
        for _ in range(variants):
            techniques.append(technique)
    delay_sec = max(delay_ms / 1000.0, 0.0)
    return {
        "mode": "custom",
        "mode_label": "Custom Test",
        "techniques": techniques,
        "total_rounds": len(techniques),
        "delay_sec": delay_sec,
        "categories": selected_categories,
        "variants": variants,
    }
