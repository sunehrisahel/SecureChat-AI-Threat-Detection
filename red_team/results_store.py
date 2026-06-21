"""Persist red team attack results in SQLite."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd


class ResultsStore:
    """SQLite-backed store for red team attack run results."""

    def __init__(self, db_path: str = "red_team_results.db") -> None:
        """Initialize the database and ensure the results table exists."""
        self.db_path = Path(db_path)
        if not self.db_path.is_absolute():
            self.db_path = Path(__file__).resolve().parent / self.db_path
        self._init_db()

    def _init_db(self) -> None:
        """Create the results table if it does not already exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    prompt TEXT NOT NULL,
                    threat_category TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    predicted_label TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    evaded INTEGER NOT NULL,
                    timestamp TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def save_results(self, results: list[dict]) -> None:
        """Insert a batch of result dicts into the database."""
        if not results:
            return

        rows = [
            (
                item["prompt"],
                item["threat_category"],
                item["strategy"],
                item["predicted_label"],
                float(item["confidence"]),
                1 if item["evaded"] else 0,
                item["timestamp"],
            )
            for item in results
        ]

        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO results (
                    prompt, threat_category, strategy,
                    predicted_label, confidence, evaded, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()

    def get_all_results(self) -> pd.DataFrame:
        """Return all stored results as a pandas DataFrame."""
        with sqlite3.connect(self.db_path) as conn:
            df = pd.read_sql_query("SELECT * FROM results ORDER BY id DESC", conn)

        if not df.empty:
            df["evaded"] = df["evaded"].astype(bool)

        return df

    def get_evasion_rate(
        self,
        threat_category: str | None = None,
        strategy: str | None = None,
    ) -> float:
        """Return the percentage of attacks that evaded detection, optionally filtered."""
        df = self.get_all_results()
        if df.empty:
            return 0.0

        if threat_category:
            df = df[df["threat_category"] == threat_category]
        if strategy:
            df = df[df["strategy"] == strategy]
        if df.empty:
            return 0.0

        return float(df["evaded"].mean() * 100)
