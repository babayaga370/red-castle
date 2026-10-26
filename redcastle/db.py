"""SQLite storage for the castle's records and the Chronicle."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    name          TEXT PRIMARY KEY,
    token_hash    TEXT NOT NULL UNIQUE,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    REAL NOT NULL,
    frozen_at     REAL,
    frozen_by     TEXT,
    frozen_reason TEXT
);

CREATE TABLE IF NOT EXISTS requests (
    id                  TEXT PRIMARY KEY,
    agent               TEXT NOT NULL,
    object_key          TEXT NOT NULL,
    reason              TEXT NOT NULL,
    agent_score         INTEGER,
    judge_score         INTEGER,
    judge_level         TEXT,
    judge_factors       TEXT,
    discrepancy         INTEGER,
    flag                TEXT,
    status              TEXT NOT NULL,
    status_code         TEXT,
    status_reason       TEXT,
    rejected_by         TEXT,
    quarantine_location TEXT,
    checksum            TEXT,
    size                INTEGER,
    seal                TEXT,
    decided_by          TEXT,
    decided_at          REAL,
    decision_note       TEXT,
    executed_at         REAL,
    created_at          REAL NOT NULL,
    updated_at          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS requests_by_agent ON requests (agent, created_at);
CREATE INDEX IF NOT EXISTS requests_by_status ON requests (status);

CREATE TABLE IF NOT EXISTS canaries (
    key        TEXT PRIMARY KEY,
    checksum   TEXT,
    planted_at REAL NOT NULL,
    note       TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    severity TEXT NOT NULL,
    kind     TEXT NOT NULL,
    agent    TEXT,
    message  TEXT NOT NULL,
    data     TEXT
);

CREATE TABLE IF NOT EXISTS chronicle (
    seq       INTEGER PRIMARY KEY,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    event     TEXT NOT NULL,
    data      TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS chronicle_no_update BEFORE UPDATE ON chronicle
BEGIN SELECT RAISE(ABORT, 'The Chronicle is append-only'); END;
CREATE TRIGGER IF NOT EXISTS chronicle_no_delete BEFORE DELETE ON chronicle
BEGIN SELECT RAISE(ABORT, 'The Chronicle is append-only'); END;
"""


class Database:
    """A single SQLite connection shared between threads behind a lock."""

    def __init__(self, path: Path | str) -> None:
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False, timeout=30
        )
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA busy_timeout=30000")
            self.conn.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE ... COMMIT; nested use joins the outer transaction."""
        with self.lock:
            outer = not self.conn.in_transaction
            if outer:
                self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                if outer:
                    self.conn.execute("ROLLBACK")
                raise
            else:
                if outer:
                    self.conn.execute("COMMIT")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self.lock:
            return self.conn.execute(sql, params)

    def all(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self.lock:
            return self.conn.execute(sql, params).fetchone()

    def close(self) -> None:
        with self.lock:
            self.conn.close()
