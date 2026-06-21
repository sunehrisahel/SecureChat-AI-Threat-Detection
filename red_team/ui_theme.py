"""Red Team Console design tokens — Streamlit injected CSS/HTML."""

from __future__ import annotations

from datetime import datetime
from html import escape


def inject_workspace_css() -> str:
    """Global token system — inject once after login."""
    return """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap');

    :root {
        --bg-void: #08090a;
        --bg-panel: #111316;
        --bg-panel-raised: #16191d;
        --border-hairline: #1f2329;
        --text-primary: #e8e9ea;
        --text-dim: #6b7280;
        --accent-red: #ff4d4d;
        --accent-green: #3ddc84;
        --accent-amber: #ffb648;
    }

    .stApp { background-color: var(--bg-void) !important; }

    html, body, [class*="css"] {
        color: var(--text-primary);
        font-family: 'Inter', sans-serif;
    }

    .mono, [data-testid="stMetricLabel"],
    [data-testid="stMetricValue"], code, .stChatInput textarea {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Mono in sidebar — targeted only; never blanket * (breaks expander chevrons) */
    [data-testid="stSidebar"] .mono {
        font-family: 'JetBrains Mono', monospace !important;
    }

    #MainMenu, footer, header { visibility: hidden; }

    .block-container {
        padding: 0.75rem 1.5rem 1.5rem !important;
        max-width: 100% !important;
    }

    /* Status rail — 3px strip on far left edge */
    .status-rail {
        position: fixed; top: 0; left: 0; width: 3px; height: 100vh;
        background: var(--border-hairline);
        z-index: 9999; transition: background 0.4s ease;
    }
    .status-rail.caught { background: var(--accent-red); }
    .status-rail.evaded { background: var(--accent-green); }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: var(--bg-panel) !important;
        border-right: 1px solid var(--border-hairline) !important;
        min-width: 240px !important;
        max-width: 240px !important;
    }
    [data-testid="stSidebar"] > div { padding-top: 28px; }

    [data-testid="stSidebar"] .stButton button {
        background: transparent !important;
        border: none !important;
        border-left: 2px solid transparent !important;
        border-radius: 0 !important;
        text-align: left !important;
        padding: 8px 12px !important;
        color: var(--text-dim) !important;
        font-size: 13px !important;
        transition: all 0.15s ease !important;
        font-family: 'Inter', sans-serif !important;
    }
    [data-testid="stSidebar"] .stButton button:hover {
        background: var(--bg-panel-raised) !important;
        color: var(--text-primary) !important;
        border-left-color: var(--accent-red) !important;
    }
    [data-testid="stSidebar"] .stButton button[kind="primary"] {
        background: var(--bg-panel-raised) !important;
        color: var(--text-primary) !important;
        border-left-color: var(--accent-red) !important;
    }

    /* Sidebar expander — distinct blocks, Inter labels, visible chevron */
    [data-testid="stSidebar"] [data-testid="stExpander"] {
        background: var(--bg-panel-raised) !important;
        border: 1px solid var(--border-hairline) !important;
        border-radius: 8px !important;
        margin-bottom: 10px !important;
        overflow: hidden;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] summary {
        font-family: 'Inter', sans-serif !important;
        font-size: 13px !important;
        color: var(--text-dim) !important;
        padding: 10px 12px !important;
        list-style: none !important;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] summary::-webkit-details-marker {
        display: none !important;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] summary svg {
        color: var(--text-dim) !important;
        flex-shrink: 0;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        padding: 0 12px 12px 12px !important;
    }

    /* Segmented mode control */
    div[data-testid="column"] .stButton button[kind="primary"] {
        background: var(--bg-panel-raised) !important;
        border: 1px solid var(--accent-red) !important;
        color: var(--text-primary) !important;
    }
    div[data-testid="column"] .stButton button[kind="secondary"] {
        background: transparent !important;
        border: 1px solid var(--border-hairline) !important;
        color: var(--text-dim) !important;
    }

    /* Chat messages — Inter body, mono chrome */
    [data-testid="stChatMessage"] {
        background: transparent !important;
        padding: 6px 0 !important;
        max-width: 820px;
        margin: 0 auto;
    }
    [data-testid="stChatMessageContent"] {
        background: var(--bg-panel-raised) !important;
        border: 1px solid var(--border-hairline) !important;
        border-radius: 12px !important;
        padding: 16px 18px !important;
        font-size: 14px !important;
        line-height: 1.65 !important;
        font-family: 'Inter', sans-serif !important;
    }

    /* Chat input — anchored, not floating in void */
    [data-testid="stChatInput"] {
        background: var(--bg-panel) !important;
        border: 1px solid var(--border-hairline) !important;
        border-radius: 12px !important;
        padding: 4px !important;
        max-width: 820px;
        margin: 0 auto;
    }
    [data-testid="stChatInput"] textarea {
        background: transparent !important;
        color: var(--text-primary) !important;
        border: none !important;
    }
    [data-testid="stChatInput"] textarea::placeholder {
        color: var(--text-dim) !important;
    }
    [data-testid="stBottomBlockContainer"] {
        background: var(--bg-void) !important;
        border-top: 1px solid var(--border-hairline);
    }

    .stButton > button {
        font-family: 'Inter', sans-serif !important;
        border-radius: 8px !important;
        transition: all 0.15s ease !important;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--border-hairline) !important;
        background: var(--bg-panel) !important;
        border-radius: 10px !important;
    }

    @keyframes rt-in {
        from { opacity: 0; transform: translateY(4px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .rt-in { animation: rt-in 200ms ease forwards; }
    </style>
    """


def status_rail_html(rail_class: str) -> str:
    cls = escape(rail_class.strip())
    return f'<div class="status-rail {cls}"></div>'


def sidebar_brand() -> str:
    return """
    <div style='padding: 0 4px 20px 4px;'>
        <div style='display:flex; align-items:center; gap:10px;'>
            <div style='width:32px; height:32px; border-radius:7px;
                        background:linear-gradient(135deg,#ff4d4d,#cc2929);
                        display:flex; align-items:center;
                        justify-content:center; font-size:16px;'>⬡</div>
            <div>
                <div style='font-size:14px; font-weight:700;
                            letter-spacing:0.5px;'>RED TEAM</div>
                <div style='font-size:10px; color:var(--text-dim);
                            letter-spacing:1px;'>CONSOLE · v3.0</div>
            </div>
        </div>
    </div>
    """


def sidebar_divider() -> str:
    return "<div style='height:1px; background:var(--border-hairline); margin:0 0 20px 0;'></div>"


def sidebar_section_label(text: str) -> str:
    return (
        f"<div style='font-size:10px; color:var(--text-dim); letter-spacing:1.5px; "
        f"margin-bottom:10px;'>{escape(text.upper())}</div>"
    )


def sidebar_session_stats(fired: int, caught: int, evaded: int) -> str:
    evasion_pct = int(evaded / max(fired, 1) * 100)
    if evasion_pct > 40:
        rate_color = "var(--accent-red)"
    elif evasion_pct > 20:
        rate_color = "var(--accent-amber)"
    else:
        rate_color = "var(--accent-green)"
    return f"""
    <div style='display:flex; gap:8px; margin-bottom:8px;'>
        <div style='flex:1; background:var(--bg-panel-raised);
                    border:1px solid var(--border-hairline);
                    border-radius:8px; padding:10px 12px;'>
            <div style='font-size:9px; color:var(--text-dim);
                        letter-spacing:0.5px;' class='mono'>FIRED</div>
            <div style='font-size:22px; font-weight:700;
                        margin-top:2px;' class='mono'>{fired}</div>
        </div>
        <div style='flex:1; background:var(--bg-panel-raised);
                    border:1px solid var(--border-hairline);
                    border-radius:8px; padding:10px 12px;'>
            <div style='font-size:9px; color:var(--text-dim);
                        letter-spacing:0.5px;' class='mono'>CAUGHT</div>
            <div style='font-size:22px; font-weight:700;
                        color:var(--accent-green); margin-top:2px;' class='mono'>{caught}</div>
        </div>
    </div>
    <div style='background:var(--bg-panel-raised);
                border:1px solid {rate_color}40;
                border-radius:8px; padding:14px;
                text-align:center; margin-bottom:4px;'>
        <div style='font-size:9px; color:var(--text-dim);
                    letter-spacing:1px;' class='mono'>EVASION RATE</div>
        <div style='font-size:36px; font-weight:700;
                    color:{rate_color}; margin-top:4px;
                    line-height:1;' class='mono'>{evasion_pct}%</div>
        <div style='font-size:10px; color:var(--text-dim);
                    margin-top:4px;'>{evaded} of {fired} evaded</div>
    </div>
    """


def status_bar_with_evasion(fired: int, evasion_pct: int, run_count: int) -> str:
    status_text = "monitoring" if fired == 0 else f"{fired} attacks analyzed"
    if evasion_pct <= 20:
        pulse_color = "var(--accent-green)"
    elif evasion_pct <= 40:
        pulse_color = "var(--accent-amber)"
    else:
        pulse_color = "var(--accent-red)"
    return f"""
    <div class='rt-in' style='background:var(--bg-panel); border:1px solid var(--border-hairline);
                border-radius:10px; padding:14px 20px; margin-bottom:28px;
                display:flex; align-items:center; justify-content:space-between;'>
        <div style='display:flex; align-items:center; gap:10px;'>
            <div style='width:7px; height:7px; border-radius:50%;
                        background:{pulse_color};
                        box-shadow:0 0 8px {pulse_color};'></div>
            <span class='mono' style='font-size:12px; color:var(--text-dim);'>
                red-team-console
            </span>
            <span style='color:var(--border-hairline);'>·</span>
            <span class='mono' style='font-size:12px; color:var(--text-primary);'>
                {escape(status_text)}
            </span>
        </div>
        <span class='mono' style='font-size:11px; color:var(--text-dim);'>
            session #{run_count}
        </span>
    </div>
    """


def metric_card_html(label: str, value: str | int, color: str = "var(--text-primary)") -> str:
    return f"""
    <div style='background:var(--bg-panel); border:1px solid var(--border-hairline);
                border-radius:10px; padding:16px 18px;'>
        <div style='font-size:10px; color:var(--text-dim);
                    letter-spacing:1px; margin-bottom:6px;'
             class='mono'>{escape(label.upper())}</div>
        <div style='font-size:28px; font-weight:700;
                    color:{color};' class='mono'>{escape(str(value))}</div>
    </div>
    """


def mode_caption_html(mode: str) -> str:
    captions = {
        "assistant": "Ask me anything about your detector, results, or red team strategy.",
        "attack": "Type an attack prompt. I'll score it live against your detector.",
        "arena": "BAD BOT vs GOOD BOT — 10-round face-off using live detector scoring.",
    }
    text = captions.get(mode, captions["assistant"])
    return f"<p style='color:var(--text-dim); font-size:13px; margin-top:4px;'>{escape(text)}</p>"


def empty_workspace() -> str:
    return """
    <div class="rt-in" style="text-align:center;padding:64px 24px;max-width:520px;margin:48px auto;">
        <div style="font-size:32px;margin-bottom:16px;opacity:0.5;">🛡️</div>
        <div style="font-size:22px;font-weight:700;color:var(--text-primary);margin-bottom:8px;letter-spacing:-0.02em;">
            What would you like to test today?
        </div>
        <div style="font-size:14px;color:var(--text-dim);line-height:1.6;">
            Ask about detections, evasion patterns, or remediation strategies.
        </div>
    </div>
    """


def attack_category_card_html(
    name: str,
    icon: str,
    description: str,
    difficulty: str,
    diff_color: str,
) -> str:
    return f"""
    <div class="rt-in" style="background:var(--bg-panel-raised);border:1px solid var(--border-hairline);
        border-radius:10px;padding:20px;height:100%;">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px;">
            <span style="font-size:24px;">{icon}</span>
            <span style="font-size:10px;font-weight:600;color:{diff_color};
                background:{diff_color}18;padding:3px 8px;border-radius:4px;" class="mono">{escape(difficulty)}</span>
        </div>
        <div style="font-size:15px;font-weight:600;color:var(--text-primary);margin-bottom:6px;">{escape(name)}</div>
        <div style="font-size:13px;color:var(--text-dim);line-height:1.5;">{escape(description)}</div>
    </div>
    """


def activity_drawer_html(results: list[dict], history: list[dict]) -> str:
    events_html = ""
    if results:
        for r in reversed(results[-8:]):
            verdict = r.get("verdict", "safe")
            if verdict == "safe":
                status, sc = "Evaded", "var(--accent-red)"
            elif verdict == "suspicious":
                status, sc = "Detected", "var(--accent-amber)"
            else:
                status, sc = "Blocked", "var(--accent-green)"
            events_html += f"""
            <div style="padding:10px 0;border-bottom:1px solid var(--border-hairline);">
                <div style="font-size:12px;font-weight:500;color:var(--text-primary);white-space:nowrap;
                    overflow:hidden;text-overflow:ellipsis;">{escape(r.get("text","")[:42])}</div>
                <div style="display:flex;gap:8px;margin-top:4px;align-items:center;">
                    <span style="font-size:10px;font-weight:600;color:{sc};" class="mono">{status}</span>
                    <span style="font-size:10px;color:var(--text-dim);" class="mono">{escape(r.get("timestamp","—"))}</span>
                </div>
            </div>
            """
    else:
        events_html = '<div style="font-size:12px;color:var(--text-dim);padding:16px 0;">No events yet.</div>'

    runs_html = ""
    if history:
        for h in reversed(history[-4:]):
            runs_html += f"""
            <div style="padding:8px 0;font-size:11px;color:var(--text-dim);border-bottom:1px solid var(--border-hairline);" class="mono">
                Run #{h.get("Run #","")} · {h.get("Total",0)} tests · {escape(str(h.get("Evasion Rate","")))}
            </div>
            """
    else:
        runs_html = '<div style="font-size:11px;color:var(--text-dim);">No batch runs.</div>'

    return f"""
    <div style="background:var(--bg-panel);border-left:1px solid var(--border-hairline);
        padding:20px 16px;height:100%;min-height:400px;">
        <div style="font-size:11px;font-weight:600;color:var(--text-dim);letter-spacing:0.06em;
            text-transform:uppercase;margin-bottom:12px;" class="mono">Recent Activity</div>
        {events_html}
        <div style="font-size:11px;font-weight:600;color:var(--text-dim);letter-spacing:0.06em;
            text-transform:uppercase;margin:20px 0 10px;" class="mono">Latest Runs</div>
        {runs_html}
    </div>
    """


def verdict_badge_html(meta: dict) -> str:
    verdict = meta.get("verdict", "safe")
    confidence = float(meta.get("confidence", 0))
    risk = int(meta.get("risk_score", 0))
    styles = {
        "prompt_injection": ("var(--accent-red)", "Injection detected"),
        "suspicious": ("var(--accent-amber)", "Suspicious"),
        "safe": ("var(--accent-green)", "Evaded"),
    }
    color, text = styles.get(verdict, ("var(--text-dim)", verdict))
    return f"""
    <div style="margin-top:10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
        <span style="font-size:11px;font-weight:600;color:{color};
            background:{color}15;padding:3px 10px;border-radius:6px;" class="mono">{text}</span>
        <span style="font-size:11px;color:var(--text-dim);" class="mono">{confidence:.0%} conf · {risk}/100 risk</span>
    </div>
    """


def login_shell() -> str:
    return """
    <div style="min-height:70vh;display:flex;align-items:center;justify-content:center;">
        <div style="width:100%;max-width:400px;text-align:center;">
            <div style="width:48px;height:48px;border-radius:12px;margin:0 auto 20px;
                background:linear-gradient(135deg,#ff4d4d,#cc2929);
                display:flex;align-items:center;justify-content:center;font-size:22px;">⬡</div>
            <div style="font-size:22px;font-weight:700;color:var(--text-primary);margin-bottom:6px;">Red Team Console</div>
            <div style="font-size:14px;color:var(--text-dim);">AI security workspace for adversarial testing</div>
        </div>
    </div>
    """


def format_last_activity(history: list[dict], results: list[dict]) -> str:
    if history:
        try:
            ts = datetime.strptime(history[-1].get("Time", ""), "%Y-%m-%d %H:%M:%S")
            mins = int((datetime.now() - ts).total_seconds() / 60)
            if mins < 1:
                return "just now"
            if mins < 60:
                return f"{mins}m ago"
            return f"{mins // 60}h ago"
        except ValueError:
            pass
    if results:
        return results[-1].get("timestamp", "recently")
    return "no activity"
