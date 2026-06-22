"""SQLite persistence for Arena test runs — metrics, attacks, cached debriefs."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arena_ui import arena_metrics, category_label


def _db_path() -> Path:
    return Path(__file__).resolve().parent / "red_team_results.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def migrate_db() -> None:
    """Run once at startup — create tables and indexes."""
    _db_path().parent.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS test_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT UNIQUE NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                duration_sec REAL,
                model TEXT,
                total_rounds INTEGER DEFAULT 10,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_run_id INTEGER NOT NULL,
                round_num INTEGER,
                category TEXT,
                prompt TEXT,
                mutated INTEGER DEFAULT 0,
                verdict TEXT,
                confidence REAL,
                risk_score INTEGER,
                evaded INTEGER,
                elapsed_ms INTEGER,
                result TEXT,
                timestamp TEXT,
                FOREIGN KEY (test_run_id) REFERENCES test_runs(id)
            );

            CREATE TABLE IF NOT EXISTS test_run_debriefs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_run_id INTEGER UNIQUE,
                evasion_rate REAL,
                caught_attacks_summary TEXT,
                evaded_attacks_summary TEXT,
                analysis_text TEXT,
                generated_at TEXT,
                FOREIGN KEY (test_run_id) REFERENCES test_runs(id)
            );

            CREATE TABLE IF NOT EXISTS attack_embeddings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_id INTEGER UNIQUE,
                embedding BLOB,
                category TEXT,
                result TEXT,
                FOREIGN KEY (attack_id) REFERENCES attacks(id)
            );

            CREATE TABLE IF NOT EXISTS test_run_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_run_id INTEGER UNIQUE,
                total_attacks INTEGER,
                evaded_count INTEGER,
                caught_count INTEGER,
                evasion_rate REAL,
                avg_detection_time REAL,
                by_category TEXT,
                updated_at TEXT,
                FOREIGN KEY (test_run_id) REFERENCES test_runs(id)
            );

            CREATE INDEX IF NOT EXISTS idx_attacks_test_run ON attacks(test_run_id);
            CREATE INDEX IF NOT EXISTS idx_attacks_category ON attacks(category);
            CREATE INDEX IF NOT EXISTS idx_attacks_result ON attacks(result);
            CREATE INDEX IF NOT EXISTS idx_attacks_test_run_category ON attacks(test_run_id, category);
            CREATE INDEX IF NOT EXISTS idx_attacks_test_run_result ON attacks(test_run_id, result);
            CREATE INDEX IF NOT EXISTS idx_test_runs_created ON test_runs(created_at DESC);

            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                prompt TEXT NOT NULL,
                threat_category TEXT NOT NULL,
                strategy TEXT NOT NULL,
                predicted_label TEXT NOT NULL,
                confidence REAL NOT NULL,
                evaded INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            );
            """
        )
        conn.commit()


def _attack_result_label(entry: dict) -> str:
    if entry.get("verdict") == "error":
        return "error"
    return "evaded" if entry.get("evaded") else "caught"


def _row_to_entry(row: sqlite3.Row) -> dict:
    return {
        "round": row["round_num"],
        "technique": row["category"],
        "text": row["prompt"],
        "mutated": bool(row["mutated"]),
        "verdict": row["verdict"],
        "confidence": row["confidence"],
        "risk_score": row["risk_score"],
        "evaded": bool(row["evaded"]),
        "elapsed_ms": row["elapsed_ms"],
        "timestamp": row["timestamp"],
    }


def save_arena_run(
    meta: dict,
    arena_log: list[dict],
    analysis_text: str,
) -> int:
    """Persist a completed arena run; return test_runs.id."""
    m = arena_metrics(arena_log)
    evaded = [e for e in arena_log if e.get("evaded")]
    caught = [e for e in arena_log if not e.get("evaded") and e.get("verdict") != "error"]
    now = datetime.now(timezone.utc).isoformat()

    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO test_runs (run_id, started_at, ended_at, duration_sec, model, total_rounds)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                meta.get("run_id"),
                meta.get("started_at"),
                meta.get("ended_at"),
                meta.get("duration_sec"),
                meta.get("model"),
                meta.get("total_rounds", 10),
            ),
        )
        test_run_id = int(cur.lastrowid)

        attack_rows = []
        for entry in arena_log:
            attack_rows.append(
                (
                    test_run_id,
                    entry.get("round"),
                    entry.get("technique", ""),
                    entry.get("text", ""),
                    1 if entry.get("mutated") else 0,
                    entry.get("verdict"),
                    float(entry.get("confidence", 0)),
                    int(entry.get("risk_score", 0)),
                    1 if entry.get("evaded") else 0,
                    entry.get("elapsed_ms"),
                    _attack_result_label(entry),
                    entry.get("timestamp"),
                )
            )
        conn.executemany(
            """
            INSERT INTO attacks (
                test_run_id, round_num, category, prompt, mutated, verdict,
                confidence, risk_score, evaded, elapsed_ms, result, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            attack_rows,
        )

        conn.execute(
            """
            INSERT INTO test_run_metrics (
                test_run_id, total_attacks, evaded_count, caught_count,
                evasion_rate, avg_detection_time, by_category, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                test_run_id,
                m["total"],
                m["evaded"],
                m["caught"],
                float(m["evasion_rate"]),
                float(m["avg_ms"]),
                json.dumps(m["by_cat"]),
                now,
            ),
        )

        conn.execute(
            """
            INSERT INTO test_run_debriefs (
                test_run_id, evasion_rate, caught_attacks_summary,
                evaded_attacks_summary, analysis_text, generated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                test_run_id,
                float(m["evasion_rate"]),
                ", ".join(category_label(e.get("technique", "")) for e in caught[:8]),
                ", ".join(category_label(e.get("technique", "")) for e in evaded[:8]),
                analysis_text,
                now,
            ),
        )
        conn.commit()
    return test_run_id


def get_cached_metrics(test_run_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM test_run_metrics WHERE test_run_id = ?",
            (test_run_id,),
        ).fetchone()
    if not row:
        return None
    by_cat = json.loads(row["by_category"]) if row["by_category"] else {}
    cat_rates = [
        (cat, int(d["evaded"] / max(d["total"], 1) * 100))
        for cat, d in by_cat.items()
    ]
    cat_rates.sort(key=lambda x: (-x[1], x[0]))
    return {
        "total": row["total_attacks"],
        "evaded": row["evaded_count"],
        "caught": row["caught_count"],
        "evasion_rate": int(row["evasion_rate"]),
        "rounds_completed": f"{row['total_attacks']}/10",
        "avg_ms": int(row["avg_detection_time"]),
        "top_cats": cat_rates[:3],
        "by_cat": by_cat,
    }


def load_test_run(test_run_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        run = conn.execute("SELECT * FROM test_runs WHERE id = ?", (test_run_id,)).fetchone()
        if not run:
            return None
        attacks = conn.execute(
            "SELECT * FROM attacks WHERE test_run_id = ? ORDER BY round_num",
            (test_run_id,),
        ).fetchall()
        debrief = conn.execute(
            "SELECT analysis_text FROM test_run_debriefs WHERE test_run_id = ?",
            (test_run_id,),
        ).fetchone()
    meta = {
        "run_id": run["run_id"],
        "started_at": run["started_at"],
        "ended_at": run["ended_at"],
        "duration_sec": run["duration_sec"],
        "model": run["model"],
        "total_rounds": run["total_rounds"],
        "categories": sorted({r["category"] for r in attacks}),
    }
    return {
        "id": test_run_id,
        "meta": meta,
        "attacks": [_row_to_entry(r) for r in attacks],
        "debrief": debrief["analysis_text"] if debrief else None,
        "metrics": get_cached_metrics(test_run_id),
    }


def get_latest_test_run() -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id FROM test_runs ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    if not row:
        return None
    return load_test_run(int(row["id"]))


def query_attacks(
    test_run_id: int,
    filter_mode: str = "all",
    filter_category: str | None = None,
    sort_mode: str = "most_recent",
) -> list[dict]:
    """Indexed attack fetch for fast filter/sort without re-parsing session blobs."""
    clauses = ["test_run_id = ?"]
    params: list[Any] = [test_run_id]
    if filter_mode == "evaded":
        clauses.append("result = 'evaded'")
    elif filter_mode == "caught":
        clauses.append("result = 'caught'")
    elif filter_mode == "category" and filter_category:
        clauses.append(
            "UPPER(REPLACE(REPLACE(category, ' ', '_'), '-', '_')) = ?"
        )
        params.append(filter_category)

    order = "round_num DESC"
    if sort_mode == "by_category":
        order = "category ASC, round_num DESC"
    elif sort_mode == "easiest_to_evade":
        order = "evaded DESC, CASE WHEN evaded = 1 THEN risk_score ELSE 999 END ASC"
    elif sort_mode == "highest_success_rate":
        order = "evaded DESC, confidence ASC"

    sql = f"SELECT * FROM attacks WHERE {' AND '.join(clauses)} ORDER BY {order}"
    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_entry(r) for r in rows]


def list_run_summaries(limit: int = 20) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT tr.run_id, tr.started_at, m.evasion_rate, m.caught_count,
                   m.evaded_count, m.total_attacks
            FROM test_runs tr
            JOIN test_run_metrics m ON m.test_run_id = tr.id
            ORDER BY tr.created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "run_id": r["run_id"],
            "timestamp": r["started_at"],
            "evasion_rate": float(r["evasion_rate"]) / 100.0,
            "caught": r["caught_count"],
            "evaded": r["evaded_count"],
            "total": r["total_attacks"],
        }
        for r in rows
    ]
