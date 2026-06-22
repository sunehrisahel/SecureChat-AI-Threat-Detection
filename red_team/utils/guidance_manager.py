"""Load and serve in-app guidance content from JSON."""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

_GUIDANCE_FILE = Path(__file__).resolve().parent.parent / "guidance_content.json"


def _normalize_category_key(name: str) -> str:
    return str(name or "").strip().lower().replace(" ", "_").replace("-", "_")


@st.cache_resource
def load_guidance_content() -> dict:
    """Load all guidance content from JSON — cached, instant."""
    with _GUIDANCE_FILE.open(encoding="utf-8") as f:
        return json.load(f)


def get_section_guidance(section_name: str) -> dict:
    """Get guidance for a specific dashboard section."""
    content = load_guidance_content()
    return content.get("sections", {}).get(section_name, {})


def get_category_guidance(category_name: str) -> dict:
    """Get guidance for an attack category (accepts labels or technique keys)."""
    content = load_guidance_content()
    categories = content.get("attack_categories", {})
    key = _normalize_category_key(category_name)
    if key in categories:
        return categories[key]
    # Strip _mutated suffix from arena variants
    base_key = key.removesuffix("_mutated")
    if base_key in categories:
        return categories[base_key]
    for cat_data in categories.values():
        if _normalize_category_key(cat_data.get("name", "")) == key:
            return cat_data
    return {}


def get_welcome_content() -> dict:
    """Get welcome wizard content."""
    content = load_guidance_content()
    return content.get("welcome", {})
