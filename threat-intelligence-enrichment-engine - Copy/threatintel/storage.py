"""SQLite persistence for enrichment history."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "threatintel.db"


def get_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path else DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_db(db_path: str | Path | None = None) -> None:
    with get_connection(db_path) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS enrichments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                normalized TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                sources_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_enrichments_normalized ON enrichments(normalized)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_enrichments_created_at ON enrichments(created_at)")


def save_result(result: dict[str, Any], db_path: str | Path | None = None) -> int:
    initialize_db(db_path)
    with get_connection(db_path) as connection:
        cursor = connection.execute(
            """INSERT INTO enrichments
                (indicator, normalized, ioc_type, risk_score, verdict, summary, evidence_json, sources_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result["indicator"], result["normalized"], result["ioc_type"], int(result["risk_score"]),
                result["verdict"], result["summary"], json.dumps(result.get("evidence", [])),
                json.dumps(result.get("sources", {})),
            ),
        )
        return int(cursor.lastrowid)


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["evidence"] = json.loads(data.pop("evidence_json"))
    data["sources"] = json.loads(data.pop("sources_json"))
    return data


def get_recent(limit: int = 100, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    initialize_db(db_path)
    with get_connection(db_path) as connection:
        rows = connection.execute("SELECT * FROM enrichments ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    return [_row_to_dict(row) for row in rows]


def get_latest(db_path: str | Path | None = None) -> list[dict[str, Any]]:
    initialize_db(db_path)
    with get_connection(db_path) as connection:
        rows = connection.execute(
            """SELECT e.* FROM enrichments e
               INNER JOIN (SELECT normalized, MAX(id) AS max_id FROM enrichments GROUP BY normalized) latest
               ON e.id = latest.max_id
               ORDER BY e.id DESC"""
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def clear_history(db_path: str | Path | None = None) -> None:
    initialize_db(db_path)
    with get_connection(db_path) as connection:
        connection.execute("DELETE FROM enrichments")
        connection.execute("DELETE FROM sqlite_sequence WHERE name='enrichments'")
