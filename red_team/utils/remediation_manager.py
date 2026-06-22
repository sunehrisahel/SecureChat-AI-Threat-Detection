"""Load per-category remediation guidance for evaded attacks."""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from components.arena_display import category_label

_REMEDIATION_FILE = Path(__file__).resolve().parent.parent / "remediation_content.json"


@st.cache_resource
def load_remediation_content() -> dict:
    with _REMEDIATION_FILE.open(encoding="utf-8") as f:
        return json.load(f)


def get_remediation(category: str) -> dict:
    content = load_remediation_content()
    key = category_label(category)
    if key in content:
        return content[key]
    return content.get("OTHER", {})
