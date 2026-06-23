"""Generate adversarial attack variants via the detector API (no local Anthropic key)."""

from __future__ import annotations

import os

from llm_client import generate_attacks as _fetch_generate_attacks


class AttackGenerator:
    """Calls server-side Claude through POST /red-team/generate-attacks."""

    def __init__(
        self,
        analyze_url: str | None = None,
        red_team_api_key: str | None = None,
        detector_api_key: str | None = None,
    ) -> None:
        self.analyze_url = (
            analyze_url
            or os.getenv("DETECTOR_URL", "http://127.0.0.1:8000/analyze").strip()
        )
        self.red_team_api_key = red_team_api_key or os.getenv("RED_TEAM_API_KEY", "")
        self.detector_api_key = detector_api_key or os.getenv("DETECTOR_API_KEY", "")
        self.last_error: str | None = None

    def test_api_key(self) -> tuple[bool, str]:
        """Verify the detector API can reach Anthropic server-side."""
        import requests
        from llm_client import _auth_headers, _red_team_url

        try:
            response = requests.get(
                _red_team_url(self.analyze_url, "/red-team/llm-health"),
                headers=_auth_headers(
                    red_team_api_key=self.red_team_api_key,
                    detector_api_key=self.detector_api_key,
                ),
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
            return bool(data.get("ok")), str(data.get("message", "Unknown"))
        except Exception as exc:
            return False, f"Could not reach detector API: {exc}"

    def generate_attacks(self, threat_category: str, strategy: str, n: int = 5) -> list[str]:
        """Generate n adversarial prompt variants for the given category and strategy."""
        self.last_error = None
        attacks, error = _fetch_generate_attacks(
            self.analyze_url,
            threat_category=threat_category,
            strategy=strategy,
            count=n,
            red_team_api_key=self.red_team_api_key,
            detector_api_key=self.detector_api_key,
        )
        if error:
            self.last_error = error
        return attacks
