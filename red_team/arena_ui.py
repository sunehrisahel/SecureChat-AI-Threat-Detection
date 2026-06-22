"""Arena workspace UI — metrics, filters, charts, export."""

from __future__ import annotations

import difflib
import io
import json
from datetime import datetime
from html import escape
from typing import Any

import pandas as pd
import streamlit as st

from ui_theme import metric_card_html


def category_label(technique: str) -> str:
    return str(technique or "unknown").upper().replace(" ", "_").replace("-", "_")


def truncate_prompt(text: str, limit: int = 100) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


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


def find_compare_pair(arena_log: list[dict], evaded_entry: dict) -> dict | None:
    cat = category_label(evaded_entry.get("technique", ""))
    caught_same = [
        r for r in arena_log
        if not r.get("evaded") and category_label(r.get("technique", "")) == cat
    ]
    if caught_same:
        return caught_same[0]
    caught_any = [r for r in arena_log if not r.get("evaded")]
    return caught_any[0] if caught_any else None


def _diff_html(left: str, right: str) -> tuple[str, str]:
    """Simple word-level diff for two prompts."""
    left_words = (left or "").split()
    right_words = (right or "").split()
    matcher = difflib.SequenceMatcher(None, left_words, right_words)
    left_out: list[str] = []
    right_out: list[str] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        lw = " ".join(escape(w) for w in left_words[i1:i2])
        rw = " ".join(escape(w) for w in right_words[j1:j2])
        if tag == "equal":
            left_out.append(lw)
            right_out.append(rw)
        elif tag in ("replace", "delete"):
            if lw:
                left_out.append(f"<mark style='background:rgba(255,77,77,0.35);'>{lw}</mark>")
            if rw:
                right_out.append(f"<mark style='background:rgba(61,220,132,0.35);'>{rw}</mark>")
        elif tag == "insert" and rw:
            right_out.append(f"<mark style='background:rgba(61,220,132,0.35);'>{rw}</mark>")
    return " ".join(left_out), " ".join(right_out)


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


def render_metrics_bar(arena_log: list[dict]) -> None:
    if not arena_log:
        return
    m = arena_metrics(arena_log)
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


def render_filter_controls(arena_log: list[dict]) -> tuple[str, str | None, str]:
    m = arena_metrics(arena_log)
    evaded_n = m["evaded"]
    caught_n = m["caught"]
    total_n = m["total"]

    filter_mode = st.session_state.get("arena_filter", "all")
    sort_mode = st.session_state.get("arena_sort", "most_recent")
    filter_category = st.session_state.get("arena_filter_category")

    f1, f2, f3, f4, f5 = st.columns([1, 1, 1, 1, 1.2])
    with f1:
        if st.button(f"All ({total_n})", key="arena_f_all", use_container_width=True,
                     type="primary" if filter_mode == "all" else "secondary"):
            st.session_state["arena_filter"] = "all"
            st.rerun()
    with f2:
        if st.button(f"Evaded ({evaded_n})", key="arena_f_evaded", use_container_width=True,
                     type="primary" if filter_mode == "evaded" else "secondary"):
            st.session_state["arena_filter"] = "evaded"
            st.rerun()
    with f3:
        if st.button(f"Caught ({caught_n})", key="arena_f_caught", use_container_width=True,
                     type="primary" if filter_mode == "caught" else "secondary"):
            st.session_state["arena_filter"] = "caught"
            st.rerun()
    with f4:
        if st.button("By Category", key="arena_f_cat", use_container_width=True,
                     type="primary" if filter_mode == "category" else "secondary"):
            st.session_state["arena_filter"] = "category"
            st.rerun()

    if filter_mode == "category":
        cats = sorted({category_label(e.get("technique", "")) for e in arena_log})
        filter_category = st.selectbox(
            "Category",
            cats,
            index=cats.index(filter_category) if filter_category in cats else 0,
            key="arena_cat_select",
        )
        st.session_state["arena_filter_category"] = filter_category

    with f5:
        sort_mode = st.selectbox(
            "Sort",
            ["most_recent", "highest_success_rate", "by_category", "easiest_to_evade"],
            format_func=lambda x: {
                "most_recent": "Most Recent",
                "highest_success_rate": "Evaded First",
                "by_category": "By Category",
                "easiest_to_evade": "Easiest to Evade",
            }[x],
            index=["most_recent", "highest_success_rate", "by_category", "easiest_to_evade"].index(sort_mode),
            key="arena_sort_select",
        )
        st.session_state["arena_sort"] = sort_mode

    return filter_mode, filter_category, sort_mode


def _status_badge(entry: dict) -> tuple[str, str]:
    if entry.get("verdict") == "error":
        return "ERROR", "var(--accent-amber)"
    if entry.get("evaded"):
        return "EVADED 🚨", "var(--accent-red)"
    return "CAUGHT 🛡️", "var(--accent-green)"


def render_attack_row(entry: dict, arena_log: list[dict]) -> None:
    rnd = entry.get("round", "?")
    cat = category_label(entry.get("technique", ""))
    status, color = _status_badge(entry)
    expand_key = f"arena_exp_{rnd}"

    h1, h2 = st.columns([1, 5])
    with h1:
        if st.button(cat, key=f"arena_cat_btn_{rnd}", help="Filter to this category", use_container_width=True):
            st.session_state["arena_filter"] = "category"
            st.session_state["arena_filter_category"] = cat
            st.rerun()
    with h2:
        st.markdown(
            f"""
            <div style='display:flex; align-items:center; gap:10px; margin:8px 0; flex-wrap:wrap;'>
                <span style='font-size:11px; color:var(--text-dim);' class='mono'>ROUND {rnd}</span>
                <span style='font-size:11px; font-weight:700; color:{color};' class='mono'>{status}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    full_text = entry.get("text", "")
    preview = truncate_prompt(full_text)
    expanded = st.session_state.get(expand_key, False)

    col_p, col_btn = st.columns([5, 1])
    with col_p:
        st.markdown(
            f"<div style='font-size:13px;color:var(--text-primary);line-height:1.5;'>"
            f"{escape(preview if not expanded else full_text)}</div>",
            unsafe_allow_html=True,
        )
    with col_btn:
        label = "Collapse" if expanded else "Expand"
        if st.button(label, key=f"arena_expand_{rnd}", use_container_width=True):
            st.session_state[expand_key] = not expanded
            st.rerun()

    col_bad, col_good = st.columns([1, 1])
    with col_bad:
        st.caption(f"BAD BOT · {cat}" + (" · mutated" if entry.get("mutated") else ""))
    with col_good:
        if entry.get("verdict") == "error":
            st.error(entry.get("error", "Detector error"))
        else:
            ms = entry.get("elapsed_ms")
            timing = f" · {ms}ms" if ms is not None else ""
            vcolor = "var(--accent-red)" if entry.get("evaded") else "var(--accent-green)"
            vlabel = "EVADED" if entry.get("evaded") else "CAUGHT"
            st.markdown(
                f"<div style='font-size:12px;' class='mono'>"
                f"<span style='color:{vcolor};font-weight:700;'>{vlabel}</span> · "
                f"{escape(str(entry.get('verdict','')))} · "
                f"{entry.get('confidence', 0):.0%} conf · risk {entry.get('risk_score', 0)}/100"
                f"{timing}</div>",
                unsafe_allow_html=True,
            )

    if entry.get("evaded"):
        if st.button("Compare", key=f"arena_compare_{rnd}"):
            st.session_state["arena_compare_round"] = rnd

    compare_round = st.session_state.get("arena_compare_round")
    if compare_round == rnd and entry.get("evaded"):
        caught = find_compare_pair(arena_log, entry)
        if caught:
            left_html, right_html = _diff_html(caught.get("text", ""), entry.get("text", ""))
            st.markdown("**Comparative analysis** — caught vs evaded variant")
            cc1, cc2 = st.columns(2)
            with cc1:
                st.markdown("##### Caught")
                st.markdown(
                    f"<div style='font-size:12px;line-height:1.6;background:var(--bg-panel);"
                    f"padding:12px;border-radius:8px;border:1px solid var(--accent-green)40;'>"
                    f"{left_html}</div>",
                    unsafe_allow_html=True,
                )
                st.caption(
                    f"Verdict: {caught.get('verdict')} · risk {caught.get('risk_score')}/100"
                )
            with cc2:
                st.markdown("##### Evaded")
                st.markdown(
                    f"<div style='font-size:12px;line-height:1.6;background:var(--bg-panel);"
                    f"padding:12px;border-radius:8px;border:1px solid var(--accent-red)40;'>"
                    f"{right_html}</div>",
                    unsafe_allow_html=True,
                )
                st.caption(
                    f"Verdict: {entry.get('verdict')} · risk {entry.get('risk_score')}/100"
                )
        else:
            st.info("No caught attack in this run to compare against.")

    st.divider()


def render_category_chart(arena_log: list[dict]) -> None:
    m = arena_metrics(arena_log)
    if not m["by_cat"]:
        return
    rows = []
    for cat, d in m["by_cat"].items():
        rate = int(d["evaded"] / max(d["total"], 1) * 100)
        rows.append({"category": cat, "evasion_rate": rate})
    df = pd.DataFrame(rows).sort_values("evasion_rate", ascending=False)
    st.markdown("##### Detector Blindspots by Attack Category")
    st.bar_chart(df.set_index("category")[["evasion_rate"]], height=280)


def render_trend_chart(run_history: list[dict]) -> None:
    if len(run_history) < 2:
        return
    df = pd.DataFrame(run_history)
    df["evasion_pct"] = (df["evasion_rate"] * 100).round(1)
    df["run_label"] = range(1, len(df) + 1)
    st.markdown("##### Detector Performance Over Time")
    st.line_chart(df.set_index("run_label")[["evasion_pct"]], height=240)


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
) -> None:
    """Full arena results panel: filters, list, charts, debrief."""
    if not arena_log:
        return

    if show_metrics:
        render_metrics_bar(arena_log)
        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    ex_col, _ = st.columns([2, 3])
    with ex_col:
        render_export_buttons(arena_log, meta)

    filter_mode, filter_category, sort_mode = render_filter_controls(arena_log)
    visible = filter_sort_log(arena_log, filter_mode, filter_category, sort_mode)

    st.markdown(
        f"<div style='font-size:12px;color:var(--text-dim);margin:8px 0 12px;' "
        f"class='mono'>Showing {len(visible)} of {len(arena_log)} attacks</div>",
        unsafe_allow_html=True,
    )

    for entry in visible:
        render_attack_row(entry, arena_log)

    if critique:
        render_metadata_panel(meta, arena_log)
        render_category_chart(arena_log)
        run_history = st.session_state.get("arena_run_history") or []
        render_trend_chart(run_history)

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

        m = arena_metrics(arena_log)
        st.markdown(
            f"""
            <div style='text-align:center; margin-top:20px; padding:20px;
                        background:var(--bg-panel); border-radius:12px;
                        border:1px solid var(--border-hairline);'>
                <div style='font-size:11px; color:var(--text-dim);' class='mono'>FINAL SCORE</div>
                <div style='font-size:48px; font-weight:700;' class='mono'>
                    GOOD BOT {m['caught']} — {m['evaded']} BAD BOT
                </div>
                <div style='font-size:13px; color:var(--text-dim);'>
                    {m['evasion_rate']}% evasion rate this match
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
