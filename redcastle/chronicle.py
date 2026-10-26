"""The Chronicle: a tamper-evident, append-only log of every decision.

Every entry is sealed with an HMAC that covers the previous entry's seal, so
altering, removing or re-ordering any entry breaks the chain from that point
on. SQLite triggers additionally refuse UPDATE and DELETE on the table.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .db import Database

log = logging.getLogger("redcastle.chronicle")
GENESIS = "0" * 64


@dataclass
class Verification:
    ok: bool
    entries: int
    broken_at: int | None = None
    problem: str | None = None


class Chronicle:
    def __init__(self, db: Database, key: bytes) -> None:
        self.db = db
        self.key = key

    def record(self, actor: str, event: str, **data: Any) -> dict:
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)
        with self.db.transaction() as conn:
            last = conn.execute("SELECT seq, hash FROM chronicle ORDER BY seq DESC LIMIT 1").fetchone()
            seq = last["seq"] + 1 if last else 1
            prev = last["hash"] if last else GENESIS
            ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            digest = self._digest(seq, ts, actor, event, payload, prev)
            conn.execute(
                "INSERT INTO chronicle (seq, ts, actor, event, data, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (seq, ts, actor, event, payload, prev, digest),
            )
        log.debug("#%d %s %s %s", seq, actor, event, payload)
        return {"seq": seq, "ts": ts, "actor": actor, "event": event, "data": data, "hash": digest}

    def _digest(self, seq: int, ts: str, actor: str, event: str, payload: str, prev: str) -> str:
        message = json.dumps([seq, ts, actor, event, payload, prev], ensure_ascii=False)
        return hmac.new(self.key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify(self) -> Verification:
        """Walk the whole chain and report the first entry that does not check out."""
        expected_prev = GENESIS
        count = 0
        rows = self.db.all("SELECT * FROM chronicle ORDER BY seq")
        for expected_seq, row in enumerate(rows, start=1):
            if row["seq"] != expected_seq:
                return Verification(False, count, expected_seq, f"entry {expected_seq} is missing")
            if row["prev_hash"] != expected_prev:
                return Verification(False, count, row["seq"], "the link to the previous entry is broken")
            digest = self._digest(row["seq"], row["ts"], row["actor"], row["event"], row["data"], row["prev_hash"])
            if not hmac.compare_digest(digest, row["hash"]):
                return Verification(False, count, row["seq"], "the entry was altered")
            expected_prev = row["hash"]
            count += 1
        return Verification(True, count)

    def entries(self, limit: int = 50, *, request_id: str | None = None) -> list[dict]:
        """Newest entries first, optionally only those about one request."""
        if request_id:
            rows = self.db.all(
                "SELECT * FROM chronicle WHERE json_extract(data, '$.request_id') = ? "
                "ORDER BY seq DESC LIMIT ?",
                (request_id, limit),
            )
        else:
            rows = self.db.all("SELECT * FROM chronicle ORDER BY seq DESC LIMIT ?", (limit,))
        return [{**dict(r), "data": json.loads(r["data"])} for r in rows]

    def after(self, seq: int, limit: int = 500) -> list[dict]:
        """Entries newer than ``seq``, oldest first (for following the Chronicle live)."""
        rows = self.db.all("SELECT * FROM chronicle WHERE seq > ? ORDER BY seq LIMIT ?", (seq, limit))
        return [{**dict(r), "data": json.loads(r["data"])} for r in rows]

    def head(self) -> dict | None:
        """The newest entry's number and seal - publish it elsewhere to detect truncation."""
        row = self.db.one("SELECT seq, ts, hash FROM chronicle ORDER BY seq DESC LIMIT 1")
        return dict(row) if row else None
