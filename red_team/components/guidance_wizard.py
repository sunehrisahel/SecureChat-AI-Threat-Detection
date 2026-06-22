"""Reusable guidance UI — welcome wizard, section toggles, category reference."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import streamlit as st

from utils.guidance_manager import (
    get_category_guidance,
    get_section_guidance,
    get_welcome_content,
    load_guidance_content,
)

_DISMISS_FILE = Path(__file__).resolve().parent.parent / ".guidance_welcome_dismissed"
_DISMISS_TTL = timedelta(hours=24)


def _welcome_dismissed() -> bool:
    if st.session_state.get("guidance_dismissed"):
        return True
    if not _DISMISS_FILE.exists():
        return False
    try:
        data = json.loads(_DISMISS_FILE.read_text(encoding="utf-8"))
        dismissed_at = datetime.fromisoformat(data["dismissed_at"])
        if datetime.now(timezone.utc) - dismissed_at < _DISMISS_TTL:
            st.session_state["guidance_dismissed"] = True
            return True
    except (json.JSONDecodeError, KeyError, ValueError, TypeError):
        pass
    return False


def _dismiss_welcome() -> None:
    st.session_state["guidance_dismissed"] = True
    _DISMISS_FILE.write_text(
        json.dumps({"dismissed_at": datetime.now(timezone.utc).isoformat()}),
        encoding="utf-8",
    )


def show_welcome_wizard() -> None:
    """Display welcome wizard on first visit (hidden for 24h after dismiss)."""
    if _welcome_dismissed():
        return

    with st.container(border=True):
        col1, col2 = st.columns([20, 1])
        with col1:
            content = get_welcome_content()
            st.markdown(f"### 🎯 {content.get('title', 'Welcome')}")
            st.markdown(content.get("content", ""))
            st.markdown("**Key Concepts:**")
            for term in content.get("key_terms", []):
                st.markdown(f"- **{term.get('term', '')}:** {term.get('definition', '')}")
        with col2:
            if st.button("✕", key="dismiss_welcome"):
                _dismiss_welcome()
                st.rerun()


def show_section_guidance(section_name: str) -> None:
    """Show inline guidance toggle for a dashboard section."""
    toggle_key = f"show_guidance_{section_name}"
    if toggle_key not in st.session_state:
        st.session_state[toggle_key] = False

    if st.button("ℹ️ Why does this matter?", key=f"guidance_toggle_{section_name}"):
        st.session_state[toggle_key] = not st.session_state[toggle_key]

    if st.session_state[toggle_key]:
        guidance = get_section_guidance(section_name)
        if not guidance:
            return
        with st.container(border=True):
            st.markdown(f"### {guidance.get('title', section_name)}")
            st.markdown(f"**Why it matters:** {guidance.get('why_matters', '')}")
            st.markdown("**How to use:**")
            for step in guidance.get("how_to_use", []):
                st.markdown(f"- {step}")
            if guidance.get("watch_for"):
                st.markdown(f"⚠️ **Watch for:** {guidance['watch_for']}")


def show_category_guidance_modal(category_name: str) -> None:
    """Show guidance for an attack category (expandable)."""
    guidance = get_category_guidance(category_name)
    if not guidance:
        return
    label = guidance.get("name", category_name)
    with st.expander(f"📚 {label} — What is this?"):
        st.markdown(f"**{label}**")
        st.markdown(f"**What it does:** {guidance.get('description', '')}")
        st.markdown(f"**Example:** `{guidance.get('example', '')}`")
        st.markdown(f"**Why defenders should care:** {guidance.get('why_matters', '')}")
        st.markdown(f"**Goal:** {guidance.get('defender_goal', '')}")


def show_attack_category_reference() -> None:
    """Sidebar reference guide for all attack categories."""
    if st.checkbox("📖 Attack Category Guide", key="guidance_category_guide"):
        content = load_guidance_content()
        for category_data in content.get("attack_categories", {}).values():
            with st.expander(f"📌 {category_data.get('name', 'Category')}"):
                st.write(category_data.get("description", ""))
                st.code(category_data.get("example", ""))
                st.info(category_data.get("why_matters", ""))
                st.write(f"🛡️ Defender goal: {category_data.get('defender_goal', '')}")
