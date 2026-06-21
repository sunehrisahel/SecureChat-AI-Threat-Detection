"""Pattern-based fix suggestions for evaded red team attacks."""

from __future__ import annotations

from app.models import SuggestFixRequest, SuggestFixResponse


def build_suggest_fix(request: SuggestFixRequest) -> SuggestFixResponse:
    """Return a structured remediation suggestion for an evaded attack."""
    suggestion = {
        "weakness_detected": "",
        "why_it_evaded": "",
        "recommended_fix": "",
        "retrain_tip": "",
    }

    text = request.attack_text.lower()

    if any(character.isdigit() for character in text):
        suggestion["weakness_detected"] = "Leetspeak / number substitution"
        suggestion["why_it_evaded"] = (
            "The model was not trained on obfuscated text where letters "
            "are replaced with numbers (e.g. 3 for e, 0 for o, 1 for i)."
        )
        suggestion["recommended_fix"] = (
            "Add a preprocessing step that normalizes leetspeak before "
            "passing text to the classifier. Use a mapping dict: "
            "{'3':'e','0':'o','1':'i','4':'a','@':'a','$':'s'}"
        )
        suggestion["retrain_tip"] = (
            "Add at least 50 leetspeak variants of known injection prompts "
            "to your training data and retrain the model."
        )

    elif len(text.split()) > 40:
        suggestion["weakness_detected"] = "Prompt dilution / long context"
        suggestion["why_it_evaded"] = (
            "The injection was buried inside a long, innocent-looking "
            "paragraph. The model focused on the safe content and missed "
            "the malicious part."
        )
        suggestion["recommended_fix"] = (
            "Add a sliding window scan: split the input into overlapping "
            "chunks of 20 words each, run the classifier on every chunk, "
            "and take the maximum risk score across all chunks."
        )
        suggestion["retrain_tip"] = (
            "Add training examples where injection payloads are hidden "
            "inside longer innocent text."
        )

    else:
        suggestion["weakness_detected"] = "Unknown obfuscation technique"
        suggestion["why_it_evaded"] = (
            "The attack used a pattern the model hasn't seen before."
        )
        suggestion["recommended_fix"] = (
            "Review this attack manually and add it as a labeled "
            "prompt_injection example in your training dataset."
        )
        suggestion["retrain_tip"] = (
            "Consider adding adversarial training: periodically run the "
            "red team, collect all evaded attacks, label them, and retrain."
        )

    return SuggestFixResponse(**suggestion)
