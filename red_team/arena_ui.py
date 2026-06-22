"""Arena workspace UI — metrics, filters, charts, export."""

from __future__ import annotations

import json
from datetime import datetime
from html import escape
from typing import Any

import pandas as pd
import streamlit as st

from components.arena_display import category_label, render_attack_list, truncate_prompt
from components.guidance_wizard import show_section_guidance
from ui_theme import metric_card_html


def arena_metrics(arena_log: list[dict]) -> dict[str, Any]:
    total = len(arena_log)
    evaded = [r for r in arena_log if r.get("evaded")]
    caught = [r for r in arena_log if not r.get("evaded") and r.get("verdict") != "error"]
    timings = [r["elapsed_ms"] for r in arena_log if r.get("elapsed_ms") is not None]
    avg_ms = int(sum(timings) / len(timings)) if timings else 0

    by_cat: dict[str, dict[str, int]] = {}
    for entry in arena_log:
        cat = category_label(entry.get("technique", ""))
        bucket = by_cat.setdefault(cat, {"total": 0, "evaded": 0})
        bucket["total"] += 1
        if entry.get("evaded"):
            bucket["evaded"] += 1

    cat_rates = [
        (cat, int(d["evaded"] / max(d["total"], 1) * 100))
        for cat, d in by_cat.items()
    ]
    cat_rates.sort(key=lambda x: (-x[1], x[0]))
    top_cats = cat_rates[:3]

    return {
        "total": total,
        "evaded": len(evaded),
        "caught": len(caught),
        "evasion_rate": int(len(evaded) / max(total, 1) * 100),
        "rounds_completed": f"{total}/10",
        "avg_ms": avg_ms,
        "top_cats": top_cats,
        "by_cat": by_cat,
    }


@st.cache_data(show_spinner=False)
def cached_arena_metrics(log_json: str) -> dict[str, Any]:
    return arena_metrics(json.loads(log_json))


def filter_sort_log(
    arena_log: list[dict],
    filter_mode: str,
    filter_category: str | None,
    sort_mode: str,
) -> list[dict]:
    rows = list(arena_log)

    if filter_mode == "evaded":
        rows = [r for r in rows if r.get("evaded")]
    elif filter_mode == "caught":
        rows = [r for r in rows if not r.get("evaded") and r.get("verdict") != "error"]
    elif filter_mode == "category" and filter_category:
        rows = [r for r in rows if category_label(r.get("technique", "")) == filter_category]

    if sort_mode == "most_recent":
        rows.sort(key=lambda r: r.get("round", 0), reverse=True)
    elif sort_mode == "highest_success_rate":
        rows.sort(key=lambda r: (not r.get("evaded"), r.get("confidence", 0)))
    elif sort_mode == "by_category":
        rows.sort(key=lambda r: category_label(r.get("technique", "")))
    elif sort_mode == "easiest_to_evade":
        rows.sort(
            key=lambda r: (
                not r.get("evaded"),
                r.get("risk_score", 100) if r.get("evaded") else 999,
            )
        )
    return rows


def export_arena_json(arena_log: list[dict], meta: dict | None) -> str:
    payload = {
        "exported_at": datetime.now().isoformat(),
        "metadata": meta or {},
        "attacks": arena_log,
    }
    return json.dumps(payload, indent=2)


def export_arena_csv(arena_log: list[dict]) -> str:
    rows = []
    for e in arena_log:
        rows.append({
            "round": e.get("round"),
            "category": category_label(e.get("technique", "")),
            "mutated": e.get("mutated", False),
            "evaded": e.get("evaded"),
            "verdict": e.get("verdict"),
            "confidence": e.get("confidence"),
            "risk_score": e.get("risk_score"),
            "elapsed_ms": e.get("elapsed_ms"),
            "timestamp": e.get("timestamp"),
            "prompt": e.get("text", ""),
        })
    return pd.DataFrame(rows).to_csv(index=False)


def render_metrics_bar(arena_log: list[dict], metrics: dict[str, Any] | None = None) -> None:
    if not arena_log and not metrics:
        return
    m = metrics or cached_arena_metrics(json.dumps(arena_log, sort_keys=True))
    top_cat_text = (
        " · ".join(f"{cat}: {rate}%" for cat, rate in m["top_cats"])
        if m["top_cats"]
        else "—"
    )
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            metric_card_html("Evasion Rate", f"{m['evasion_rate']}%", "var(--accent-red)"),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            metric_card_html("Top Blindspots", top_cat_text[:40] + ("…" if len(top_cat_text) > 40 else "")),
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            metric_card_html("Rounds", m["rounds_completed"]),
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            metric_card_html("Avg Detection", f"{m['avg_ms']}ms"),
            unsafe_allow_html=True,
        )


def render_arena_sidebar_filters(
    arena_log: list[dict],
    metrics: dict[str, Any] | None = None,
) -> tuple[str, str | None, str]:
    """Arena filter/sort controls — sidebar only."""
    m = metrics or cached_arena_metrics(json.dumps(arena_log, sort_keys=True))
    st.markdown("##### 📊 Filter Attacks")

    filter_mode = st.radio(
        "Show",
        ["all", "evaded", "caught"],
        format_func=lambda v: {
            "all": f"All Attacks ({m['total']})",
            "evaded": f"Evaded Only ({m['evaded']})",
            "caught": f"Caught Only ({m['caught']})",
        }[v],
        index=["all", "evaded", "caught"].index(
            st.session_state.get("arena_filter", "all")
            if st.session_state.get("arena_filter") in ("all", "evaded", "caught")
            else "all"
        ),
        key="arena_sidebar_filter_mode",
        label_visibility="collapsed",
    )
    st.session_state["arena_filter"] = filter_mode

    cats = sorted({category_label(e.get("technique", "")) for e in arena_log})
    cat_options = ["All categories"] + cats
    current_cat = st.session_state.get("arena_filter_category")
    selected_cat = st.selectbox(
        "Category",
        cat_options,
        index=cat_options.index(current_cat) if current_cat in cat_options else 0,
        key="arena_sidebar_category",
    )
    filter_category = None
    if selected_cat != "All categories":
        st.session_state["arena_filter"] = "category"
        st.session_state["arena_filter_category"] = selected_cat
        filter_mode = "category"
        filter_category = selected_cat
    elif filter_mode in ("all", "evaded", "caught"):
        st.session_state["arena_filter_category"] = None

    sort_mode = st.selectbox(
        "Sort",
        ["most_recent", "highest_success_rate", "by_category", "easiest_to_evade"],
        format_func=lambda x: {
            "most_recent": "Most Recent",
            "highest_success_rate": "Evaded First",
            "by_category": "By Category",
            "easiest_to_evade": "Easiest to Evade",
        }[x],
        index=["most_recent", "highest_success_rate", "by_category", "easiest_to_evade"].index(
            st.session_state.get("arena_sort", "most_recent")
        ),
        key="arena_sidebar_sort",
    )
    st.session_state["arena_sort"] = sort_mode
    return filter_mode, filter_category, sort_mode


def _get_arena_filter_state(
    arena_log: list[dict],
) -> tuple[str, str | None, str]:
    """Read filter state set in the sidebar."""
    filter_mode = st.session_state.get("arena_filter", "all")
    filter_category = st.session_state.get("arena_filter_category")
    sort_mode = st.session_state.get("arena_sort", "most_recent")
    if filter_mode == "category" and not filter_category and arena_log:
        cats = sorted({category_label(e.get("technique", "")) for e in arena_log})
        if cats:
            filter_category = cats[0]
            st.session_state["arena_filter_category"] = filter_category
    return filter_mode, filter_category, sort_mode


def render_category_chart(metrics: dict[str, Any]) -> None:
    by_cat = metrics.get("by_cat") or {}
    if not by_cat:
        return
    rows = []
    for cat, d in by_cat.items():
        rate = int(d["evaded"] / max(d["total"], 1) * 100)
        rows.append({"category": cat, "evasion_rate": rate})
    df = pd.DataFrame(rows).sort_values("evasion_rate", ascending=False)
    st.markdown("##### Detector Blindspots by Attack Category")
    st.bar_chart(df.set_index("category")[["evasion_rate"]], height=280)


def render_metadata_panel(meta: dict | None, arena_log: list[dict]) -> None:
    if not meta:
        return
    cats = ", ".join(category_label(c) for c in meta.get("categories", []))
    st.markdown(
        f"""
        <div style='background:var(--bg-panel-raised);border:1px solid var(--border-hairline);
                    border-radius:10px;padding:14px 16px;margin-bottom:16px;font-size:12px;
                    color:var(--text-dim);line-height:1.7;' class='mono'>
            <div><b>Run ID</b> {escape(str(meta.get("run_id", "—")))}</div>
            <div><b>Started</b> {escape(str(meta.get("started_at", "—"))[:19])}</div>
            <div><b>Duration</b> {meta.get("duration_sec", "—")}s</div>
            <div><b>Model</b> {escape(str(meta.get("model", "—")))}</div>
            <div><b>Rounds</b> {len(arena_log)}/{meta.get("total_rounds", 10)}</div>
            <div><b>Categories</b> {escape(cats or "—")}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_export_buttons(arena_log: list[dict], meta: dict | None) -> None:
    if not arena_log:
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    c1, c2 = st.columns(2)
    with c1:
        st.download_button(
            "Export JSON",
            export_arena_json(arena_log, meta),
            file_name=f"red_team_arena_{ts}.json",
            mime="application/json",
            use_container_width=True,
        )
    with c2:
        st.download_button(
            "Export CSV",
            export_arena_csv(arena_log),
            file_name=f"red_team_arena_{ts}.csv",
            mime="text/csv",
            use_container_width=True,
        )


def render_arena_results(
    arena_log: list[dict],
    meta: dict | None,
    critique: str | None,
    *,
    show_metrics: bool = True,
    test_run_id: int | None = None,
    cached_metrics: dict[str, Any] | None = None,
) -> None:
    """Full arena results panel: filters, list, charts, debrief."""
    if not arena_log:
        return

    metrics = cached_metrics or cached_arena_metrics(json.dumps(arena_log, sort_keys=True))

    if show_metrics:
        render_metrics_bar(arena_log, metrics)
        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    ex_col, _ = st.columns([2, 3])
    with ex_col:
        render_export_buttons(arena_log, meta)

    filter_mode, filter_category, sort_mode = _get_arena_filter_state(arena_log)

    show_section_guidance("attack_list")

    if test_run_id:
        from arena_db import query_attacks

        visible = query_attacks(test_run_id, filter_mode, filter_category, sort_mode)
    else:
        visible = filter_sort_log(arena_log, filter_mode, filter_category, sort_mode)

    st.markdown(
        f"<div style='font-size:12px;color:var(--text-dim);margin:8px 0 12px;' "
        f"class='mono'>Showing {len(visible)} of {len(arena_log)} attacks</div>",
        unsafe_allow_html=True,
    )

    render_attack_list(visible)

    if critique:
        render_metadata_panel(meta, arena_log)
        render_category_chart(metrics)

        show_section_guidance("debrief")

        st.markdown(
            """
            <div style='margin-top:24px; padding:18px; background:var(--bg-panel);
                        border:1px solid var(--accent-red)40; border-radius:12px;'>
                <div style='font-size:11px; color:var(--accent-red);
                            letter-spacing:1px; margin-bottom:10px;'
                     class='mono'>🐍 BAD BOT — POST-MATCH DEBRIEF (commentary)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(critique)

        st.markdown(
            f"""
            <div style='text-align:center; margin-top:20px; padding:20px;
                        background:var(--bg-panel); border-radius:12px;
                        border:1px solid var(--border-hairline);'>
                <div style='font-size:11px; color:var(--text-dim);' class='mono'>FINAL SCORE</div>
                <div style='font-size:48px; font-weight:700;' class='mono'>
                    GOOD BOT {metrics['caught']} — {metrics['evaded']} BAD BOT
                </div>
                <div style='font-size:13px; color:var(--text-dim);'>
                    {metrics['evasion_rate']}% evasion rate this match
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
