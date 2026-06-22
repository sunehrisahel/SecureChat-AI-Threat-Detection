"""Live Arena fight visualization — scoreboard, timeline, no detailed attack cards."""

from __future__ import annotations

from html import escape
from typing import Any

import streamlit as st

from arena_ui import arena_metrics
from components.arena_display import category_label
from components.category_legend import get_category_color, render_arena_category_legend


def _current_streak(arena_log: list[dict]) -> tuple[str, str]:
    if not arena_log:
        return "—", "neutral"
    ordered = sorted(arena_log, key=lambda r: r.get("round", 0))
    last_evaded = bool(ordered[-1].get("evaded"))
    count = 0
    for entry in reversed(ordered):
        if bool(entry.get("evaded")) == last_evaded:
            count += 1
        else:
            break
    if last_evaded:
        return f"Bad Bot: {count}", "bad"
    return f"Good Bot: {count}", "good"


def _critical_categories(metrics: dict[str, Any], threshold: int = 50) -> list[str]:
    blindspots = []
    for cat, data in (metrics.get("by_cat") or {}).items():
        rate = int(data["evaded"] / max(data["total"], 1) * 100)
        if rate >= threshold:
            blindspots.append(cat.replace("_", " ").title())
    return blindspots[:5]


def render_fight_scoreboard(metrics: dict[str, Any]) -> None:
    evaded = metrics["evaded"]
    caught = metrics["caught"]
    col1, col2, col3 = st.columns([2, 1, 2])

    with col1:
        st.markdown(
            f"""
            <div style="text-align:center;padding:20px;
                        background:linear-gradient(135deg,#FF4444,#FF8833);
                        border-radius:10px;color:white;">
                <h2 style="margin:0;">🤖 BAD BOT</h2>
                <p style="font-size:32px;font-weight:700;margin:10px 0;">{evaded}</p>
                <p style="font-size:12px;opacity:0.85;margin:0;">Attacks Evaded</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            """
            <div style="text-align:center;padding:20px;background:#333;
                        border-radius:10px;color:white;margin-top:12px;">
                <h3 style="margin:0;">VS</h3>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f"""
            <div style="text-align:center;padding:20px;
                        background:linear-gradient(135deg,#44DD44,#22BB44);
                        border-radius:10px;color:white;">
                <h2 style="margin:0;">🛡️ GOOD BOT</h2>
                <p style="font-size:32px;font-weight:700;margin:10px 0;">{caught}</p>
                <p style="font-size:12px;opacity:0.85;margin:0;">Attacks Blocked</p>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_fight_progress(arena_log: list[dict], total_rounds: int = 10) -> None:
    completed = len(arena_log)
    progress = completed / max(total_rounds, 1)
    st.markdown("### ⚡ Battle Progress")
    c1, c2 = st.columns([3, 1])
    with c1:
        st.progress(min(progress, 1.0))
    with c2:
        label = "Complete" if completed >= total_rounds else "In progress"
        st.caption(f"{completed}/{total_rounds} Rounds · {label}")


def render_live_stats(metrics: dict[str, Any], arena_log: list[dict]) -> None:
    streak, _ = _current_streak(arena_log)
    detection_accuracy = 100 - metrics["evasion_rate"]
    st.markdown("### 📊 Live Statistics")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Evasion Rate", f"{metrics['evasion_rate']}%")
    with c2:
        st.metric("Detection Accuracy", f"{detection_accuracy}%")
    with c3:
        st.metric("Avg Detection Time", f"{metrics['avg_ms']}ms")
    with c4:
        st.metric("Current Streak", streak)


def render_attack_timeline(arena_log: list[dict], limit: int = 10) -> None:
    st.markdown("### 🔄 Attack Timeline")
    st.caption("Round summary only — open **Arena Results** for full analysis and fixes.")
    if not arena_log:
        st.info("No rounds yet. Start a face-off to populate the timeline.")
        return

    ordered = sorted(arena_log, key=lambda r: r.get("round", 0), reverse=True)[:limit]
    for entry in ordered:
        rnd = entry.get("round", "?")
        cat = category_label(entry.get("technique", ""))
        color = get_category_color(cat)
        if entry.get("verdict") == "error":
            emoji, result, status_color = "⚠️", "ERROR", "#ffb648"
        elif entry.get("evaded"):
            emoji, result, status_color = "🚨", "EVADED", "#FF4444"
        else:
            emoji, result, status_color = "✅", "CAUGHT", "#22DD44"

        c1, c2, c3 = st.columns([1, 2.5, 1.5])
        with c1:
            st.markdown(f"**Round {rnd}**")
        with c2:
            st.markdown(
                f'<span style="background:{color};color:#fff;padding:4px 10px;'
                f'border-radius:12px;font-size:11px;font-weight:700;">'
                f"{escape(cat)}</span>",
                unsafe_allow_html=True,
            )
        with c3:
            st.markdown(
                f'<span style="color:{status_color};font-weight:700;">'
                f"{emoji} {result}</span>",
                unsafe_allow_html=True,
            )


def render_fight_summary(metrics: dict[str, Any]) -> None:
    blindspots = _critical_categories(metrics)
    bs_text = ", ".join(f"**{b}**" for b in blindspots) if blindspots else "none flagged yet"
    st.markdown("### 📋 Battle Summary")
    st.info(
        f"**Evasion rate: {metrics['evasion_rate']}%** — Bad Bot evaded {metrics['evaded']} of "
        f"{metrics['total']} attacks. Critical blindspots: {bs_text}.\n\n"
        "Open **Arena Results** for per-attack breakdowns and remediation steps."
    )


def render_arena_fight(
    arena_log: list[dict],
    metrics: dict[str, Any] | None = None,
    *,
    total_rounds: int = 10,
) -> None:
    """Full live-fight view (no detailed attack cards)."""
    if not arena_log:
        return
    metrics = metrics or arena_metrics(arena_log)
    render_fight_scoreboard(metrics)
    st.divider()
    render_fight_progress(arena_log, total_rounds)
    st.divider()
    render_live_stats(metrics, arena_log)
    st.divider()
    st.markdown("### 🎨 Attack Categories Performance")
    render_arena_category_legend()
    st.divider()
    render_attack_timeline(arena_log)
    st.divider()
    render_fight_summary(metrics)

    st.markdown(
        f"""
        <div style='text-align:center;margin-top:16px;padding:20px;
                    background:var(--bg-panel);border-radius:12px;
                    border:1px solid var(--border-hairline);'>
            <div style='font-size:11px;color:var(--text-dim);' class='mono'>FINAL SCORE</div>
            <div style='font-size:42px;font-weight:700;' class='mono'>
                GOOD BOT {metrics['caught']} — {metrics['evaded']} BAD BOT
            </div>
            <div style='font-size:13px;color:var(--text-dim);margin-top:6px;'>
                {metrics['evasion_rate']}% evasion rate
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
