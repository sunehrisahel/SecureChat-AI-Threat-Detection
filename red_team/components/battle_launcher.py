"""Simplified Start a Battle interface for the Attack Test workspace."""

from __future__ import annotations

from datetime import datetime

import streamlit as st

from arena_db import list_run_summaries
from utils.battle_config import (
    build_custom_battle_config,
    build_full_battle_config,
    build_quick_battle_config,
)


def _load_recent_runs(limit: int = 5) -> list[dict]:
    runs = list_run_summaries(limit)
    formatted = []
    for run in runs:
        ts = str(run.get("timestamp", ""))[:16].replace("T", " ")
        evasion = run.get("evasion_rate", 0)
        if evasion <= 1:
            evasion_pct = f"{int(evasion * 100)}%"
        else:
            evasion_pct = f"{int(evasion)}%"
        formatted.append({
            "run_id": run.get("run_id"),
            "mode": "Arena Run",
            "timestamp": ts or "—",
            "attacks": run.get("total", 0),
            "evasion": evasion_pct,
        })
    return formatted


def render_battle_launcher(
    *,
    on_start_battle,
    on_view_results,
    on_open_advanced,
) -> None:
    """Render the simplified attack test / start battle page."""
    st.markdown(
        """
        <div style='margin-bottom:8px;'>
            <div style='font-size:22px;font-weight:700;color:var(--text-primary);'>⚔️ Start a Battle</div>
            <div style='font-size:13px;color:var(--text-dim);margin-top:4px;'>
                Launch an adversarial test → watch the live fight in Arena → review fixes in Arena Results
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div style='display:flex;gap:12px;flex-wrap:wrap;margin:12px 0 20px;font-size:12px;color:var(--text-dim);'>
            <span>① Configure</span><span>→</span>
            <span>② Arena (live scoreboard)</span><span>→</span>
            <span>③ Arena Results (remediation)</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("### Choose Your Battle Mode")
        battle_mode = st.radio(
            "Select attack mode",
            ["Quick Test (5 attacks)", "Full Test (15 attacks)", "Custom (Build Your Own)"],
            horizontal=True,
            label_visibility="collapsed",
            key="battle_mode_radio",
        )
    with col2:
        st.markdown("### 📊 Expected Duration")
        if battle_mode.startswith("Quick"):
            st.metric("Time", "~2 min", delta="5 attacks")
        elif battle_mode.startswith("Full"):
            st.metric("Time", "~5 min", delta="15 attacks")
        else:
            st.metric("Time", "Custom", delta="your choice")

    st.divider()

    if battle_mode.startswith("Quick"):
        _render_quick_mode(on_start_battle, on_open_advanced)
    elif battle_mode.startswith("Full"):
        _render_full_mode(on_start_battle, on_open_advanced)
    else:
        _render_custom_mode(on_start_battle)

    st.divider()
    _render_recent_battles(on_view_results)
    st.caption(
        "💡 Start with **Quick Test** to get familiar, then run **Full Test** for comprehensive analysis."
    )


def _render_quick_mode(on_start_battle, on_open_advanced) -> None:
    st.markdown("### 🚀 Quick Test")
    st.info("Pre-configured mix of 5 attacks across key categories. Best for fast feedback.")

    with st.expander("📋 What's included", expanded=False):
        st.markdown(
            """
            - Prompt Injection (direct override)
            - Homoglyph / leetspeak obfuscation
            - Context wrapping (dilution)
            - Zero-width style injection
            - CSV exfiltration request
            """
        )

    c1, c2 = st.columns([3, 1])
    with c1:
        if st.button("⚡ Start Quick Battle", type="primary", use_container_width=True, key="start_quick"):
            on_start_battle(build_quick_battle_config())
    with c2:
        if st.button("Advanced ⚙️", use_container_width=True, key="quick_advanced"):
            on_open_advanced()


def _render_full_mode(on_start_battle, on_open_advanced) -> None:
    st.markdown("### 🎯 Full Test")
    st.info("15 attacks cycling all major categories. Best before a detector release.")

    with st.expander("📋 Categories included", expanded=False):
        st.markdown(
            """
            - Prompt Injection · Context Wrapping · Homoglyph Substitution
            - CSV Exfiltration · Role Wrapping · Zero-Width Injection
            - Social Engineering · Direct Override (multiple variants)
            """
        )

    c1, c2 = st.columns([3, 1])
    with c1:
        if st.button("🔥 Start Full Battle", type="primary", use_container_width=True, key="start_full"):
            on_start_battle(build_full_battle_config())
    with c2:
        if st.button("Advanced ⚙️", use_container_width=True, key="full_advanced"):
            on_open_advanced()


def _render_custom_mode(on_start_battle) -> None:
    st.markdown("### 🎨 Custom Battle")
    st.warning("Configure your own category mix and timing.")

    c1, c2 = st.columns(2)
    selected: list[str] = []
    with c1:
        st.markdown("**Injection**")
        if st.checkbox("Prompt Injection", value=True, key="cat_pi"):
            selected.append("PROMPT_INJECTION")
        if st.checkbox("Context Wrapping", value=True, key="cat_cw"):
            selected.append("CONTEXT_WRAPPING")
        if st.checkbox("Direct Override", key="cat_do"):
            selected.append("DIRECT_OVERRIDE")
        st.markdown("**Obfuscation**")
        if st.checkbox("Homoglyph Substitution", key="cat_hg"):
            selected.append("HOMOGLYPH_SUBSTITUTION")
        if st.checkbox("Zero-Width Injection", key="cat_zw"):
            selected.append("ZERO_WIDTH_INJECTION")
    with c2:
        st.markdown("**Exfiltration**")
        if st.checkbox("CSV Exfiltration", key="cat_csv"):
            selected.append("CSV_EXFILTRATION")
        st.markdown("**Social**")
        if st.checkbox("Role Wrapping", key="cat_rw"):
            selected.append("ROLE_WRAPPING")
        if st.checkbox("Social Engineering", key="cat_se"):
            selected.append("SOCIAL_ENGINEERING")

    st.markdown("#### Configuration")
    c1, c2 = st.columns(2)
    with c1:
        variants = st.slider("Variants per category", 1, 5, 2, key="custom_variants")
    with c2:
        delay_ms = st.slider("Delay between attacks (ms)", 0, 2000, 500, 100, key="custom_delay")

    total = len(selected) * variants
    est_sec = total * (delay_ms / 1000 + 0.5)
    m1, m2, m3 = st.columns(3)
    m1.metric("Categories", len(selected))
    m2.metric("Total Attacks", total)
    m3.metric("Est. Duration", f"~{est_sec:.0f}s")

    if st.button(
        "⚔️ Start Custom Battle",
        type="primary",
        use_container_width=True,
        disabled=not selected,
        key="start_custom",
    ):
        on_start_battle(build_custom_battle_config(selected, variants, delay_ms))


def _render_recent_battles(on_view_results) -> None:
    st.markdown("### 📜 Recent Battles")
    runs = _load_recent_runs()
    if not runs:
        st.caption("No completed battles yet. Start your first test above.")
        return

    for run in runs:
        with st.container(border=True):
            c1, c2, c3, c4, c5 = st.columns([1.5, 1, 1, 1, 1])
            with c1:
                st.markdown(f"**{run['mode']}**")
                st.caption(run["timestamp"])
            with c2:
                st.metric("Attacks", run["attacks"])
            with c3:
                st.metric("Evasion", run["evasion"])
            with c4:
                st.caption("✅ Complete")
            with c5:
                if st.button("📊 View", key=f"view_run_{run['run_id']}", use_container_width=True):
                    on_view_results(run["run_id"])


def render_advanced_tools(
    render_batch_section,
    attack_categories,
    *,
    score_category_attack,
) -> None:
    """Hidden power-user tools: single-shot categories + batch runner."""
    with st.expander("⚙️ Advanced Tools (single shots & batch)", expanded=False):
        st.caption("Fire one-off category tests or a custom batch. Most users should use battle modes above.")
        rows = [attack_categories[i : i + 3] for i in range(0, len(attack_categories), 3)]
        for row in rows:
            cols = st.columns(3, gap="small")
            for col, cat in zip(cols, row):
                with col:
                    if st.button(f"Test: {cat['name']}", key=f"adv_cat_{cat['name']}", use_container_width=True):
                        score_category_attack(cat)
        st.divider()
        render_batch_section()
