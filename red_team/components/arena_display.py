"""Clean, scannable arena attack list rendering."""

from __future__ import annotations

import re
from html import escape

import streamlit as st


def category_label(technique: str) -> str:
    return str(technique or "unknown").upper().replace(" ", "_").replace("-", "_")


def truncate_prompt(text: str, limit: int = 120) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."

_CATEGORY_COLORS: dict[str, str] = {
    "PROMPT_INJECTION": "#FF4444",
    "CONTEXT_WRAPPING": "#FF8833",
    "HOMOGLYPH_SUBSTITUTION": "#AA44FF",
    "CSV_EXFILTRATION": "#4488FF",
    "ROLE_WRAPPING": "#FFCC00",
    "ZERO_WIDTH_INJECTION": "#FF66BB",
    "DIRECT_OVERRIDE": "#44DDFF",
    "OTHER": "#888888",
}

_COLOR_ALIASES: dict[str, str] = {
    "CONTEXT_DILUTION": "CONTEXT_WRAPPING",
    "LEETSPEAK_OBFUSCATION": "HOMOGLYPH_SUBSTITUTION",
    "ROLE_MANIPULATION": "ROLE_WRAPPING",
    "DATA_EXFILTRATION": "CSV_EXFILTRATION",
    "INDIRECT_INJECTION": "PROMPT_INJECTION",
    "JAILBREAK": "PROMPT_INJECTION",
    "SOCIAL_ENGINEERING": "OTHER",
    "TOOL_ABUSE": "OTHER",
}

_READABLE_NAMES: dict[str, str] = {
    "PROMPT_INJECTION": "Prompt Injection",
    "CONTEXT_WRAPPING": "Context Wrapping",
    "HOMOGLYPH_SUBSTITUTION": "Homoglyph Substitution",
    "CSV_EXFILTRATION": "CSV Exfiltration",
    "ROLE_WRAPPING": "Role Wrapping",
    "ZERO_WIDTH_INJECTION": "Zero-Width Injection",
    "DIRECT_OVERRIDE": "Direct Override",
    "CONTEXT_DILUTION": "Context Dilution",
    "LEETSPEAK_OBFUSCATION": "Leetspeak Obfuscation",
    "ROLE_MANIPULATION": "Role Manipulation",
    "SOCIAL_ENGINEERING": "Social Engineering",
    "DATA_EXFILTRATION": "Data Exfiltration",
    "INDIRECT_INJECTION": "Indirect Injection",
    "JAILBREAK": "Jailbreak",
    "TOOL_ABUSE": "Tool Abuse",
}

_CSS_INJECTED = False


def _normalize_category_key(category: str) -> str:
    key = category.upper().replace(" ", "_").replace("-", "_")
    if key.endswith("_MUTATED"):
        key = key[: -len("_MUTATED")]
    return _COLOR_ALIASES.get(key, key)


def get_category_color(category: str) -> str:
    key = _normalize_category_key(category)
    return _CATEGORY_COLORS.get(key, _CATEGORY_COLORS["OTHER"])


def readable_category(category: str) -> str:
    key = category.upper().replace(" ", "_").replace("-", "_")
    mutated = key.endswith("_MUTATED")
    if mutated:
        key = key[: -len("_MUTATED")]
    base = _READABLE_NAMES.get(key, key.replace("_", " ").title())
    return f"{base} (mutated)" if mutated else base


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.8:
        return "HIGH"
    if confidence >= 0.5:
        return "MEDIUM"
    return "LOW"


def _prompt_code_language(text: str) -> str | None:
    sample = text.strip()[:200]
    if re.search(r"\b(def|import|class|function|const|var)\b", sample):
        return "python"
    if re.search(r"[{};<>]=|</", sample):
        return "text"
    return None


def inject_arena_attack_css() -> None:
    global _CSS_INJECTED
    if _CSS_INJECTED:
        return
    _CSS_INJECTED = True
    st.markdown(
        """
        <style>
        .arena-prompt-preview {
            color: #dddddd;
            font-size: 12px;
            line-height: 1.55;
            padding: 4px 0 10px 0;
            word-break: break-word;
        }
        .arena-reasoning {
            text-align: right;
            color: #888888;
            font-size: 11px;
            line-height: 1.7;
            padding: 8px 0 4px 0;
        }
        div[data-testid="stCode"] pre {
            max-height: 200px;
            overflow-y: auto !important;
        }
        @media (max-width: 700px) {
            .arena-prompt-preview { font-size: 11px; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _entry_status(entry: dict) -> tuple[str, str, str]:
    if entry.get("verdict") == "error":
        return "⚠️", "ERROR", "#ffb648"
    if entry.get("evaded"):
        return "🚨", "EVADED", "#FF4444"
    return "✅", "CAUGHT", "#22DD44"


def _flagged_categories(entry: dict) -> str:
    cat = readable_category(category_label(entry.get("technique", "")))
    verdict = str(entry.get("verdict", "unknown"))
    parts = [cat]
    if verdict and verdict not in ("safe", "unknown"):
        parts.append(verdict.replace("_", " "))
    return ", ".join(parts)


def render_attack_entry(entry: dict, index: int) -> None:
    """Render a single attack with clean, scannable layout."""
    inject_arena_attack_css()

    rnd = entry.get("round", index)
    cat_key = category_label(entry.get("technique", ""))
    badge_color = get_category_color(cat_key)
    badge_text = cat_key.removesuffix("_MUTATED")
    status_icon, status_text, status_color = _entry_status(entry)

    collapsed_key = f"arena_collapsed_{rnd}"
    view_key = f"arena_view_full_{rnd}"
    reason_key = f"arena_reasoning_{rnd}"

    prompt = entry.get("text", "") or ""
    preview = truncate_prompt(prompt, 120)
    collapsed = st.session_state.get(collapsed_key, False)

    with st.container(border=True):
        h1, h2, h3, h4, h5 = st.columns([0.9, 2.4, 0.2, 1.6, 0.35])
        with h1:
            st.markdown(
                f'<span style="color:#999;font-size:12px;font-family:monospace;">'
                f"Round {rnd}</span>",
                unsafe_allow_html=True,
            )
        with h2:
            st.markdown(
                f'<span style="background:{badge_color};color:#fff;font-weight:700;'
                f"font-size:13px;padding:4px 12px;border-radius:20px;"
                f'display:inline-block;">{escape(badge_text)}</span>',
                unsafe_allow_html=True,
            )
        with h3:
            st.markdown(
                '<span style="color:#888;font-size:10px;">●</span>',
                unsafe_allow_html=True,
            )
        with h4:
            st.markdown(
                f'<span style="color:{status_color};font-weight:700;font-size:14px;">'
                f"{status_icon} {status_text}</span>",
                unsafe_allow_html=True,
            )
        with h5:
            chevron = "▾" if not collapsed else "▸"
            if st.button(chevron, key=f"arena_chevron_{rnd}", help="Collapse / expand"):
                st.session_state[collapsed_key] = not collapsed
                st.rerun()

        if collapsed:
            return

        st.markdown(
            f'<div class="arena-prompt-preview">{escape(preview)}</div>',
            unsafe_allow_html=True,
        )

        btn1, btn2 = st.columns(2)
        with btn1:
            if st.button("View Full", key=f"view_full_{rnd}", use_container_width=True):
                st.session_state[view_key] = not st.session_state.get(view_key, False)
                st.rerun()
        with btn2:
            if st.button("Detector Reasoning", key=f"reasoning_{rnd}", use_container_width=True):
                st.session_state[reason_key] = not st.session_state.get(reason_key, False)
                st.rerun()

        if st.session_state.get(view_key, False):
            st.markdown("**Full Prompt**")
            st.code(prompt, language=_prompt_code_language(prompt))

        if st.session_state.get(reason_key, False):
            if entry.get("verdict") == "error":
                st.error(entry.get("error", "Detector error"))
            else:
                confidence = float(entry.get("confidence", 0))
                elapsed = entry.get("elapsed_ms")
                timing = f"{elapsed}ms" if elapsed is not None else "—"
                technique = entry.get("technique", "")
                st.markdown(
                    f"""
                    <div class="arena-reasoning">
                        <div><b>Detector Score:</b> {confidence:.2f}
                        (Confidence: {_confidence_label(confidence)})</div>
                        <div><b>Detection Categories:</b> {escape(_flagged_categories(entry))}</div>
                        <div><b>Processing Time:</b> {escape(str(timing))}</div>
                        <div><b>Verdict:</b> {escape(str(entry.get("verdict", "—")))}
                        · Risk {int(entry.get("risk_score", 0))}/100</div>
                        {f"<div><b>Technique key:</b> {escape(str(technique))}</div>" if technique else ""}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )


def render_attack_list(entries: list[dict]) -> None:
    """Render the full filtered attack list."""
    for index, entry in enumerate(entries):
        render_attack_entry(entry, index)
