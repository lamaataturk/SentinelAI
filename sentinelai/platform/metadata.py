"""L-6: a small key/value table that records where a database's data came from.

It lives in the same SQLite file as the shared memory but in its own table, so
the `messages` table (and every agent that reads it) is untouched.

    data_source = "fixtures"  -> written by scripts/init_demo.py
    data_source = "agents"    -> real agent output (set by whoever runs them)
"""
from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

DATA_SOURCES = ("fixtures", "agents")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _connect(db_path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS platform_meta ("
        " key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL)"
    )
    return conn


def get_meta(db_path, key: str) -> str | None:
    if not Path(db_path).exists():
        return None
    with closing(_connect(db_path)) as conn:
        row = conn.execute("SELECT value FROM platform_meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def all_meta(db_path) -> dict[str, str]:
    if not Path(db_path).exists():
        return {}
    with closing(_connect(db_path)) as conn:
        return dict(conn.execute("SELECT key, value FROM platform_meta ORDER BY key"))


def set_meta(db_path, key: str, value: str) -> None:
    if key == "data_source" and value not in DATA_SOURCES:
        raise ValueError(f"data_source must be one of {DATA_SOURCES}")
    with closing(_connect(db_path)) as conn, conn:
        conn.execute(
            "INSERT INTO platform_meta (key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, value, utc_now()),
        )


def message_count(db_path) -> int:
    """Number of agent messages in the file (0 if the file or table does not exist)."""
    if not Path(db_path).exists():
        return 0
    with closing(sqlite3.connect(db_path)) as conn:
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages'"
        ).fetchone()
        return conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] if exists else 0
