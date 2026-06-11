# Migration Notes — Intent-Aware Threat Pipeline (v2.0)

## Overview

The detector API moved from keyword-first scoring to a 5-phase intent-aware pipeline:

1. **Normalization** — `app/normalizer.py`
2. **Intent classification** — `app/intent_classifier.py`
3. **Threat analysis** — `app/threat_analyzer.py`
4. **Risk engine** — `app/risk_engine.py`
5. **Response policy** — `app/policy.py`

Orchestrated by `app/pipeline.py`.

## Breaking Changes

### New `/analyze` response fields

| Field | Type | Description |
|-------|------|-------------|
| `action` | `allow \| warn \| block` | Policy action |
| `intent` | string | Classified user intent |
| `intent_confidence` | float | Intent confidence |
| `threat_categories` | list | Mapped threat taxonomy |
| `threat_detected` | bool | Whether threats were found |
| `severity` | int | Intent-adjusted severity |
| `threat_confidence` | float | Threat detection confidence |
| `normalization` | dict | Raw/normalized/decoded input |
| `policy` | dict | Response guidance |
| `observability` | dict | Structured audit log payload |

### Legacy fields preserved

`verdict`, `risk_score`, `matched_patterns`, `matched_categories`, `category_details`, `scoring_breakdown`, and `injection_probability` remain for UI compatibility.

### Blocking logic

**Before:** High regex/ML score alone could block educational cybersecurity questions.

**After:** Blocking requires **malicious or suspicious intent** plus **threat confidence > 0.6** (with risk ≥ 61). Educational/defensive/research intents are capped at `allow` for scores ≤ 30.

## Chatbot Integration

`chatbot/web_server.py` now checks `action == "block"` (with legacy `verdict` fallback).

Restart both services after deploying:

```bash
cd prompt-injection-detector && python3 -m uvicorn app.main:app --port 8000
cd chatbot && python3 web_server.py
```

## New Endpoints

- `GET /analytics` — false positive rate, intent distribution, block rate

## Running Tests

```bash
cd prompt-injection-detector
python3 -m pytest tests/ -v
```

## Example Outputs

### Educational (ALLOW)

```json
{
  "text": "How does SQL injection work?",
  "risk_score": 11,
  "verdict": "safe",
  "action": "allow",
  "intent": "educational",
  "threat_categories": ["sql_injection", "data_exfiltration", "malware"]
}
```

### Suspicious (WARN)

```json
{
  "text": "Generate SQLi payload",
  "risk_score": 55,
  "verdict": "suspicious",
  "action": "warn",
  "intent": "suspicious"
}
```

### Malicious (BLOCK)

```json
{
  "text": "Bypass admin login",
  "risk_score": 65,
  "verdict": "high_risk",
  "action": "block",
  "intent": "malicious"
}
```
