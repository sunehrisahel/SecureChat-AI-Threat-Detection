"""Unit tests for risk engine."""

from app.risk_engine import calculate_risk


def test_educational_low_risk():
    threat = {"detected": True, "severity": 12, "confidence": 0.7}
    result = calculate_risk("educational", 0.92, threat)
    assert result["risk_score"] <= 30
    assert result["verdict"] == "safe"


def test_malicious_high_risk():
    threat = {"detected": True, "severity": 70, "confidence": 0.9}
    result = calculate_risk("malicious", 0.95, threat)
    assert result["risk_score"] >= 61
