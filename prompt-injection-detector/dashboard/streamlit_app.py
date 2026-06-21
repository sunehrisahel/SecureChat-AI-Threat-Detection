"""Streamlit monitoring dashboard for the prompt injection detector."""

from __future__ import annotations

import os
import secrets
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(_PROJECT_ROOT / ".env")
load_dotenv(_PROJECT_ROOT / "prompt-injection-detector" / ".env")

API_BASE_URL = os.getenv("DETECTOR_DASHBOARD_URL", "http://localhost:8000")
REFRESH_INTERVAL_SECONDS = 10
MAX_LOGIN_ATTEMPTS = 5

VERDICT_COLORS = {
    "safe": "#28a745",
    "suspicious": "#ffc107",
    "high_risk": "#fd7e14",
    "blocked": "#dc3545",
}

VERDICT_BADGE_STYLES = {
    "safe": "background-color: #d4edda; color: #155724; padding: 8px 16px; border-radius: 8px; font-weight: bold;",
    "suspicious": "background-color: #fff3cd; color: #856404; padding: 8px 16px; border-radius: 8px; font-weight: bold;",
    "high_risk": "background-color: #ffe5d0; color: #a04000; padding: 8px 16px; border-radius: 8px; font-weight: bold;",
    "blocked": "background-color: #f8d7da; color: #721c24; padding: 8px 16px; border-radius: 8px; font-weight: bold;",
}


def _dashboard_password() -> str:
    return (
        os.getenv("DETECTOR_DASHBOARD_PASSWORD")
        or os.getenv("RED_TEAM_PASSWORD")
        or ""
    ).strip()


def _password_matches(entered: str, expected: str) -> bool:
    if not expected:
        return False
    return secrets.compare_digest(entered.encode("utf-8"), expected.encode("utf-8"))


def _init_session_state() -> None:
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "login_failures" not in st.session_state:
        st.session_state["login_failures"] = 0


def _auth_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    admin_key = (os.getenv("ADMIN_API_KEY") or "").strip()
    detector_key = (os.getenv("DETECTOR_API_KEY") or "").strip()
    token = admin_key or detector_key
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _api_get(endpoint: str) -> dict | list | None:
    try:
        response = requests.get(
            f"{API_BASE_URL}{endpoint}",
            headers=_auth_headers(),
            timeout=5,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        st.error(f"API request failed: {exc}")
        return None


def _api_post_analyze(text: str, source: str = "streamlit-dashboard") -> dict | None:
    try:
        response = requests.post(
            f"{API_BASE_URL}/analyze",
            json={"text": text, "source": source},
            headers=_auth_headers(),
            timeout=10,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        st.error(f"Analysis request failed: {exc}")
        return None


def _render_verdict_badge(verdict: str) -> None:
    style = VERDICT_BADGE_STYLES.get(verdict, VERDICT_BADGE_STYLES["safe"])
    st.markdown(
        f'<div style="{style}">Verdict: {verdict.upper().replace("_", " ")}</div>',
        unsafe_allow_html=True,
    )


def _style_log_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    def _row_color(row: pd.Series) -> list[str]:
        color = VERDICT_COLORS.get(row.get("verdict", "safe"), "#ffffff")
        return [f"background-color: {color}22"] * len(row)

    if df.empty:
        return df

    styled = df.style.apply(_row_color, axis=1)
    return styled


def _render_login() -> None:
    st.title("Detector Dashboard Login")
    st.caption("Enter your password to access the monitoring dashboard.")

    expected = _dashboard_password()
    if not expected:
        st.warning(
            "Set DETECTOR_DASHBOARD_PASSWORD (or RED_TEAM_PASSWORD) in the project root `.env` "
            "and restart the dashboard."
        )

    if st.session_state.get("login_failures", 0) >= MAX_LOGIN_ATTEMPTS:
        st.error("Too many failed login attempts. Refresh the page to try again.")
        return

    password = st.text_input("Password", type="password", key="detector_login_password")
    if st.button("Login", type="primary"):
        if _password_matches(password, expected):
            st.session_state["authenticated"] = True
            st.session_state["login_failures"] = 0
            st.rerun()
        else:
            st.session_state["login_failures"] = st.session_state.get("login_failures", 0) + 1
            st.error("Incorrect password")


def _render_dashboard() -> None:
    with st.sidebar:
        if st.button("Logout"):
            st.session_state["authenticated"] = False
            st.session_state["login_failures"] = 0
            st.rerun()

    st.title("🛡️ AI Prompt Injection Detector")
    st.caption("Real-time monitoring dashboard connected to FastAPI backend")

    health = _api_get("/health")
    if health and health.get("status") == "ok":
        st.success("Backend is healthy")
    else:
        st.warning("Backend may be unavailable. Ensure uvicorn is running on port 8000.")

    st.divider()

    st.header("Live Input Tester")
    user_text = st.text_area(
        "Enter text to analyze",
        height=150,
        placeholder="Type a prompt to test for injection attacks...",
    )

    if st.button("Analyze", type="primary"):
        if not user_text.strip():
            st.warning("Please enter some text to analyze.")
        else:
            result = _api_post_analyze(user_text.strip())
            if result:
                col1, col2 = st.columns([1, 2])
                with col1:
                    st.metric("Risk Score", result["risk_score"])
                    _render_verdict_badge(result["verdict"])
                with col2:
                    st.progress(result["risk_score"] / 100)
                    st.write(f"**Injection Probability:** {result['injection_probability']:.2%}")
                    st.write(f"**Regex Matched:** {'Yes' if result['regex_matched'] else 'No'}")

                if result["matched_patterns"]:
                    st.write("**Matched Patterns:**")
                    tags = " ".join(
                        f'<span style="background-color:#e9ecef;padding:4px 10px;'
                        f'border-radius:12px;margin:2px;display:inline-block;">{p}</span>'
                        for p in result["matched_patterns"]
                    )
                    st.markdown(tags, unsafe_allow_html=True)

    st.divider()

    st.header("Detection Log")
    logs = _api_get("/logs")
    if logs is not None:
        if not logs:
            st.info("No detections logged yet.")
        else:
            df = pd.DataFrame(logs)
            display_df = df.copy()
            if "text" in display_df.columns:
                display_df["text"] = display_df["text"].apply(
                    lambda t: (t[:60] + "...") if isinstance(t, str) and len(t) > 60 else t
                )

            columns = ["timestamp", "source", "verdict", "risk_score", "text"]
            available = [c for c in columns if c in display_df.columns]
            display_df = display_df[available]

            st.dataframe(_style_log_dataframe(display_df), use_container_width=True)

            st.divider()
            st.header("Analytics")

            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                st.subheader("Verdict Distribution")
                if "verdict" in df.columns:
                    verdict_counts = df["verdict"].value_counts().reset_index()
                    verdict_counts.columns = ["verdict", "count"]
                    st.bar_chart(verdict_counts.set_index("verdict"))

            with chart_col2:
                st.subheader("Risk Scores (Last 50 Requests)")
                if "risk_score" in df.columns:
                    recent = df.tail(50).reset_index(drop=True)
                    recent["request_index"] = range(len(recent))
                    chart_data = recent.set_index("request_index")[["risk_score"]]
                    st.line_chart(chart_data)

    st.caption(f"Auto-refreshing every {REFRESH_INTERVAL_SECONDS} seconds")
    time.sleep(REFRESH_INTERVAL_SECONDS)
    st.rerun()


def main() -> None:
    st.set_page_config(
        page_title="Prompt Injection Detector",
        page_icon="🛡️",
        layout="wide",
    )
    _init_session_state()

    if st.session_state.get("authenticated"):
        _render_dashboard()
    else:
        _render_login()


if __name__ == "__main__":
    main()
