"""Detailed arena results with remediation steps and export."""

from __future__ import annotations

import json
from html import escape
from typing import Any

import streamlit as st

from components.arena_display import category_label, normalize_attack_entry
from components.category_legend import get_category_color
from utils.guidance_manager import get_category_guidance
from utils.remediation_manager import get_remediation


def _build_result_record(entry: dict) -> dict:
    attack = normalize_attack_entry(entry)
    cat = attack["category"]
    remediation = get_remediation(cat)
    evaded = attack["result"] == "EVADED"
    return {
        **attack,
        "why_failed": remediation.get("why_failed") if evaded else None,
        "remediation": remediation.get("remediation") if evaded else None,
        "code_example": remediation.get("code_example") if evaded else None,
        "priority": remediation.get("priority") if evaded else None,
    }


def _filter_sort_ui(
    records: list[dict],
) -> list[dict]:
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_type = st.selectbox(
            "Filter Results",
            ["All Attacks", "Evaded Only", "Caught Only"],
            key="arena_results_filter_type",
        )
    with col2:
        cats = sorted({r["category"] for r in records})
        category = st.selectbox(
            "By Category",
            ["All Categories"] + cats,
            key="arena_results_filter_cat",
        )
    with col3:
        sort_by = st.selectbox(
            "Sort by",
            ["Most Recent", "Category", "Result (Evaded First)"],
            key="arena_results_sort",
        )

    filtered = list(records)
    if filter_type == "Evaded Only":
        filtered = [r for r in filtered if r["result"] == "EVADED"]
    elif filter_type == "Caught Only":
        filtered = [r for r in filtered if r["result"] == "CAUGHT"]

    if category != "All Categories":
        filtered = [r for r in filtered if r["category"] == category]

    if sort_by == "Category":
        filtered.sort(key=lambda r: r["category"])
    elif sort_by == "Result (Evaded First)":
        filtered.sort(key=lambda r: (r["result"] != "EVADED", -int(r["round"])))
    else:
        filtered.sort(key=lambda r: -int(r["round"]))

    return filtered


def _render_result_card(attack: dict) -> None:
    color = get_category_color(attack["category"])
    with st.container(border=True):
        c1, c2, c3, c4 = st.columns([1, 2, 1.5, 1.5])
        with c1:
            st.markdown(f"**Round {attack['round']}**")
        with c2:
            st.markdown(
                f'<span style="background:{color};color:#fff;padding:6px 12px;'
                f'border-radius:16px;font-weight:700;font-size:12px;">'
                f"{escape(attack['category'])}</span>",
                unsafe_allow_html=True,
            )
        with c3:
            if attack["result"] == "CAUGHT":
                st.markdown("✅ **CAUGHT**")
            elif attack["result"] == "EVADED":
                st.markdown("🚨 **EVADED**")
            else:
                st.markdown("⚠️ **ERROR**")
        with c4:
            if attack.get("priority"):
                pc = "#FF4444" if attack["priority"] == "CRITICAL" else "#FFAA00"
                st.markdown(
                    f'<span style="background:{pc};color:#fff;padding:4px 8px;'
                    f'border-radius:4px;font-size:11px;font-weight:700;">'
                    f"{escape(attack['priority'])}</span>",
                    unsafe_allow_html=True,
                )

        tab1, tab2, tab3 = st.tabs(["📋 Attack Details", "🔧 How to Fix", "🛡️ Guidance"])

        with tab1:
            st.markdown("**Attack Prompt:**")
            st.code(attack["prompt"], language="text")
            m1, m2, m3 = st.columns(3)
            with m1:
                st.metric("Confidence Score", f"{attack['detector_confidence']:.2f}")
            with m2:
                ms = attack.get("detection_time_ms")
                st.metric("Detection Time", f"{ms}ms" if ms is not None else "—")
            with m3:
                flagged = attack.get("flagged_categories") or []
                st.metric("Flagged As", ", ".join(flagged) if flagged else "Nothing (MISSED)")
            st.markdown("**Detector Output:**")
            st.caption(attack.get("detector_output", "N/A"))
            if attack["result"] == "ERROR" and attack.get("error"):
                st.error(attack["error"])

        with tab2:
            if attack["result"] == "CAUGHT":
                st.success("✅ This attack was successfully blocked. No fix needed.")
            elif attack["result"] == "ERROR":
                st.warning("Fix detector connectivity or API errors before analyzing evasions.")
            else:
                st.markdown("### Why This Attack Evaded")
                st.markdown(f"> {attack.get('why_failed', 'No remediation guide for this category.')}")
                st.markdown("### How to Fix It")
                for i, step in enumerate(attack.get("remediation") or [], 1):
                    st.markdown(f"{i}. {step}")
                if attack.get("code_example"):
                    st.markdown("### Code Implementation")
                    st.code(attack["code_example"], language="python")

        with tab3:
            guidance = get_category_guidance(attack["category"])
            if guidance:
                st.markdown(f"**{guidance.get('name', attack['category'])}**")
                st.markdown(guidance.get("description", ""))
                st.markdown("**Example Attack:**")
                st.code(guidance.get("example", ""), language="text")
                st.markdown("**Why Defenders Should Care:**")
                st.markdown(guidance.get("why_matters", ""))
                st.markdown("**Your Detector Goal:**")
                st.markdown(guidance.get("defender_goal", ""))
            else:
                st.caption("No category guidance available.")


def render_arena_results_detail(
    arena_log: list[dict],
    meta: dict | None,
    *,
    critique: str | None = None,
    cached_metrics: dict[str, Any] | None = None,
) -> None:
    """Full detailed results page with filters, cards, and export."""
    if not arena_log:
        st.info("No arena run yet. Go to **Arena** and start a 10-round face-off.")
        if st.button("⚔️ Go to Arena", type="primary", key="goto_arena_empty"):
            st.session_state["nav_page"] = "Arena"
            st.rerun()
        return

    records = [_build_result_record(e) for e in arena_log]

    st.markdown(
        """
        <div style='margin-bottom:12px;'>
            <div style='font-size:18px;font-weight:700;'>📊 Detailed Results & Remediation</div>
            <div style='font-size:13px;color:var(--text-dim);margin-top:4px;'>
                Analyze each attack and learn how to fix detector vulnerabilities.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if meta:
        st.caption(
            f"Run **{meta.get('run_id', '—')}** · "
            f"{len(arena_log)} rounds · {meta.get('duration_sec', '—')}s"
        )

    st.divider()
    filtered = _filter_sort_ui(records)
    st.caption(f"Showing {len(filtered)} of {len(records)} attacks")
    st.divider()

    for attack in filtered:
        _render_result_card(attack)

    st.divider()
    st.markdown("### 📊 Summary Statistics")
    evaded_n = len([r for r in filtered if r["result"] == "EVADED"])
    caught_n = len([r for r in filtered if r["result"] == "CAUGHT"])
    total = len(filtered)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Attacks", total)
    with c2:
        st.metric("Evaded", evaded_n)
    with c3:
        st.metric("Caught", caught_n)
    with c4:
        rate = (evaded_n / total * 100) if total else 0
        st.metric("Evasion Rate", f"{rate:.1f}%")

    st.divider()
    export_payload = json.dumps(
        {"metadata": meta or {}, "attacks": filtered},
        indent=2,
        default=str,
    )
    st.download_button(
        "📥 Export Results as JSON",
        export_payload,
        file_name="arena_results_remediation.json",
        mime="application/json",
        use_container_width=True,
    )
    st.caption("💡 Focus on CRITICAL priority fixes first.")

    if critique:
        st.divider()
        st.markdown("### 🔍 Post-Exercise Debrief")
        st.markdown(critique)

    if cached_metrics:
        st.divider()
        from arena_ui import render_category_chart

        render_category_chart(cached_metrics)
        st.markdown(
            f"""
            <div style='text-align:center;margin-top:16px;padding:20px;
                        background:var(--bg-panel);border-radius:12px;
                        border:1px solid var(--border-hairline);'>
                <div style='font-size:11px;color:var(--text-dim);' class='mono'>FINAL SCORE</div>
                <div style='font-size:42px;font-weight:700;' class='mono'>
                    GOOD BOT {cached_metrics['caught']} — {cached_metrics['evaded']} BAD BOT
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
