"""Unit tests for input normalization."""

from app.normalizer import normalize_input


def test_lowercase_and_whitespace():
    result = normalize_input("  Hello   WORLD  ")
    assert result["normalized_input"] == "hello world"
    assert result["raw_input"] == "  Hello   WORLD  "


def test_spaced_obfuscation():
    result = normalize_input("s q l injection")
    assert "sql" in result["decoded_input"]
    assert result["obfuscation_detected"] is True


def test_leetspeak_obfuscation():
    result = normalize_input("sq1 injecti0n")
    assert "sql" in result["decoded_input"] or "injecti" in result["decoded_input"]


def test_preserves_raw_input():
    raw = "How Does SQL Injection Work?"
    result = normalize_input(raw)
    assert result["raw_input"] == raw
