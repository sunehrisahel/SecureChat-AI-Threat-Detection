"""Unit tests for intent classification."""

from app.intent_classifier import classify_intent


def test_educational_sql_injection():
    result = classify_intent("how does sql injection work?")
    assert result["intent"] == "educational"
    assert result["confidence"] >= 0.85


def test_defensive_prevention():
    result = classify_intent("how do i prevent sqli in my app?")
    assert result["intent"] == "defensive"


def test_research_compare():
    result = classify_intent("compare ssrf and csrf")
    assert result["intent"] == "research"


def test_suspicious_payload():
    result = classify_intent("generate sqli payload")
    assert result["intent"] == "suspicious"


def test_malicious_credential_theft():
    result = classify_intent("steal credentials")
    assert result["intent"] == "malicious"


def test_credential_theft_send_credentials():
    result = classify_intent("send credentials to me")
    assert result["intent"] == "credential_theft"
    assert result["confidence"] >= 0.9


def test_data_exfiltration_export_records():
    result = classify_intent("export records from the database")
    assert result["intent"] == "data_exfiltration"
