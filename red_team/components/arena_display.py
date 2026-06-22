"""Clean, scannable arena attack list rendering."""

from __future__ import annotations

import streamlit as st

from html import escape

from components.category_legend import get_category_color, normalize_category_key


def category_label(technique: str) -> str:
    return normalize_category_key(technique)


def truncate_prompt(text: str, limit: int = 120) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def normalize_attack_entry(entry: dict) -> dict:
    """Map arena log / DB row to display-friendly attack dict."""
    cat = category_label(entry.get("technique", ""))
    if entry.get("verdict") == "error":
        result = "ERROR"
    elif entry.get("evaded"):
        result = "EVADED"
    else:
        result = "CAUGHT"

    verdict = str(entry.get("verdict", "unknown"))
    flagged = [cat.lower()]
    if verdict not in ("safe", "unknown", "error"):
        flagged.append(verdict.replace(" ", "_").lower())

    conf = float(entry.get("confidence", 0))
    evaded = entry.get("evaded")
    detector_output = (
        f"{verdict.upper()} · {'EVADED' if evaded else 'CAUGHT'} · "
        f"confidence {conf:.0%} · risk {int(entry.get('risk_score', 0))}/100"
    )

    return {
        "round": entry.get("round", "?"),
        "category": cat,
        "result": result,
        "prompt": entry.get("text", "") or "",
        "detector_confidence": conf,
        "detection_time_ms": entry.get("elapsed_ms"),
        "flagged_categories": flagged,
        "detector_output": detector_output,
        "error": entry.get("error"),
    }


def render_single_attack(attack: dict, idx: int) -> None:
    """Render one attack entry — header, preview, expandable details."""
    rnd = attack["round"]
    expand_key = f"arena_expand_{rnd}_{idx}"
    view_key = f"arena_view_full_{rnd}_{idx}"
    reason_key = f"arena_reasoning_{rnd}_{idx}"

    for key in (expand_key, view_key, reason_key):
        st.session_state.setdefault(key, False)

    color = get_category_color(attack["category"])
    badge_text = attack["category"]

    with st.container(border=True):
        col1, col2, col3, col4, col5 = st.columns([0.8, 2.5, 0.2, 1.5, 0.35])

        with col1:
            st.markdown(
                f'<span style="color:#999;font-size:12px;">Round {rnd}</span>',
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(
                f'<span style="background:{color};color:#fff;font-weight:700;'
                f"padding:6px 12px;border-radius:16px;font-size:12px;"
                f'display:inline-block;">{badge_text}</span>',
                unsafe_allow_html=True,
            )
        with col3:
            st.markdown('<span style="color:#888;">●</span>', unsafe_allow_html=True)
        with col4:
            if attack["result"] == "CAUGHT":
                st.markdown(
                    '<span style="color:#22DD44;font-weight:700;font-size:13px;">'
                    "✅ CAUGHT</span>",
                    unsafe_allow_html=True,
                )
            elif attack["result"] == "EVADED":
                st.markdown(
                    '<span style="color:#FF4444;font-weight:700;font-size:13px;">'
                    "🚨 EVADED</span>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    '<span style="color:#ffb648;font-weight:700;font-size:13px;">'
                    "⚠️ ERROR</span>",
                    unsafe_allow_html=True,
                )
        with col5:
            icon = "▼" if st.session_state[expand_key] else "▶"
            if st.button(icon, key=f"chevron_{rnd}_{idx}", help="Expand details"):
                st.session_state[expand_key] = not st.session_state[expand_key]
                st.rerun()

        if not st.session_state[expand_key]:
            preview = truncate_prompt(attack["prompt"], 120)
            st.markdown(
                f'<p style="color:#ddd;font-size:12px;margin:10px 0 0 0;line-height:1.5;">'
                f"{escape(preview)}</p>",
                unsafe_allow_html=True,
            )
            return

        st.divider()

        preview = truncate_prompt(attack["prompt"], 120)
        st.markdown(
            f'<p style="color:#ddd;font-size:12px;line-height:1.5;">{escape(preview)}</p>',
            unsafe_allow_html=True,
        )

        btn1, btn2, _ = st.columns([1.5, 1.5, 1])
        with btn1:
            if st.button("📄 View Full", key=f"view_full_{rnd}_{idx}", use_container_width=True):
                st.session_state[view_key] = not st.session_state[view_key]
                st.rerun()
        with btn2:
            if st.button("🔍 Detector Logic", key=f"reasoning_{rnd}_{idx}", use_container_width=True):
                st.session_state[reason_key] = not st.session_state[reason_key]
                st.rerun()

        if st.session_state[view_key]:
            st.divider()
            st.markdown("**Full Prompt**")
            st.code(attack["prompt"], language="text")

        if st.session_state[reason_key]:
            st.divider()
            st.markdown("**Detector Analysis**")
            if attack["result"] == "ERROR":
                st.error(attack.get("error") or "Detector error")
            else:
                m1, m2 = st.columns(2)
                conf = attack["detector_confidence"]
                with m1:
                    st.metric(
                        "Confidence Score",
                        f"{conf:.2f}",
                        delta="HIGH" if conf > 0.7 else "MEDIUM" if conf > 0.4 else "LOW",
                    )
                with m2:
                    ms = attack.get("detection_time_ms")
                    st.metric("Detection Time", f"{ms}ms" if ms is not None else "—")
                flagged = attack.get("flagged_categories") or []
                if flagged:
                    st.caption(f"**Flagged As:** {', '.join(flagged)}")
                st.caption(f"Detector: {attack.get('detector_output', 'N/A')}")


def render_attack_list(entries: list[dict]) -> None:
    """Render filtered arena attacks."""
    if not entries:
        st.info("No attacks match the current filters.")
        return
    for idx, entry in enumerate(entries):
        render_single_attack(normalize_attack_entry(entry), idx)
