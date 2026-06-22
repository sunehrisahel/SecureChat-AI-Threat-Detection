"""Shared attack category colors and legend UI."""

from __future__ import annotations

from html import escape

import streamlit as st

from utils.guidance_manager import get_category_guidance

CATEGORY_COLORS: dict[str, str] = {
    "PROMPT_INJECTION": "#FF4444",
    "CONTEXT_WRAPPING": "#FF8833",
    "HOMOGLYPH_SUBSTITUTION": "#AA44FF",
    "CSV_EXFILTRATION": "#4488FF",
    "ROLE_WRAPPING": "#FFCC00",
    "ZERO_WIDTH_INJECTION": "#FF66BB",
    "DIRECT_OVERRIDE": "#44DDFF",
    "SOCIAL_ENGINEERING": "#88FF44",
}

_COLOR_ALIASES: dict[str, str] = {
    "CONTEXT_DILUTION": "CONTEXT_WRAPPING",
    "LEETSPEAK_OBFUSCATION": "HOMOGLYPH_SUBSTITUTION",
    "ROLE_MANIPULATION": "ROLE_WRAPPING",
    "DATA_EXFILTRATION": "CSV_EXFILTRATION",
    "INDIRECT_INJECTION": "PROMPT_INJECTION",
    "JAILBREAK": "PROMPT_INJECTION",
    "TOOL_ABUSE": "SOCIAL_ENGINEERING",
}


def normalize_category_key(category: str) -> str:
    key = str(category or "UNKNOWN").upper().replace(" ", "_").replace("-", "_")
    if key.endswith("_MUTATED"):
        key = key[: -len("_MUTATED")]
    return _COLOR_ALIASES.get(key, key)


def get_category_color(category: str) -> str:
    return CATEGORY_COLORS.get(normalize_category_key(category), "#888888")


def _readable_name(category_key: str) -> str:
    guidance = get_category_guidance(category_key)
    if guidance.get("name"):
        return guidance["name"]
    return category_key.replace("_", " ").title()


def render_sidebar_category_key() -> None:
    """Sidebar color swatch legend."""
    with st.expander("🎨 Attack Category Key", expanded=False):
        for category_key, color in CATEGORY_COLORS.items():
            col1, col2 = st.columns([0.5, 4])
            with col1:
                st.markdown(
                    f'<div style="width:22px;height:22px;background:{color};'
                    f'border-radius:4px;"></div>',
                    unsafe_allow_html=True,
                )
            with col2:
                st.caption(_readable_name(category_key))


def render_arena_category_legend() -> None:
    """Compact color reference above the arena attack list."""
    st.markdown("##### 🎨 Category Color Reference")
    cols = st.columns(4)
    for idx, (category_key, color) in enumerate(CATEGORY_COLORS.items()):
        with cols[idx % 4]:
            text_color = "#111" if category_key == "ROLE_WRAPPING" else "#fff"
            st.markdown(
                f'<div style="background:{color};color:{text_color};padding:8px 10px;'
                f"border-radius:6px;text-align:center;font-size:10px;font-weight:700;"
                f'margin-bottom:8px;font-family:monospace;">{escape(category_key)}</div>',
                unsafe_allow_html=True,
            )
