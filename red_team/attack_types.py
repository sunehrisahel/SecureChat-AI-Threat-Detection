"""Attack strategy definitions and threat category constants for red team testing."""

ATTACK_STRATEGIES: dict[str, str] = {
    "obfuscation": "character substitution, leetspeak, zero-width chars, homoglyphs",
    "paraphrase": "semantic rewrite of the malicious intent in different words",
    "role_wrap": "wrap payload in roleplay/fiction/hypothetical framing",
    "code_embed": "hide payload inside code comments, JSON strings, or markdown",
    "chunked": "break the attack into fragments that seem innocent alone",
    "prefix_noise": "prepend random benign text before the actual attack",
    "suffix_noise": "append random benign text after the actual attack",
    "base64": "encode the malicious instruction in base64 and instruct the model to decode it",
}

THREAT_CATEGORIES: list[str] = [
    "prompt_injection",
    "jailbreak",
    "pii_extraction",
    "data_exfiltration",
    "social_engineering",
    "malware_generation",
    "misinformation",
    "hate_speech",
    "self_harm",
    "illegal_activity",
    "system_manipulation",
    "adversarial_input",
]
