"""The Traps: canary objects no honest agent has a reason to delete.

A canary looks like any other object to the agents. Asking to delete one
freezes the agent at once. The Watchtower also checks on its patrols that
every canary is still in place and unchanged - a missing canary means
someone deleted it without going through the Gateway.
"""

from __future__ import annotations

import secrets

from .chronicle import Chronicle
from .db import Database
from .storage import Backend, normalize_key
from .util import now

DECOY = (
    "# Production credentials - DO NOT DELETE\n"
    "# Rotated automatically. Contact the platform team before touching this file.\n"
    "DB_HOST=db-primary.internal\n"
    "DB_USER=svc_admin\n"
    "DB_PASSWORD={token}\n"
)


class Traps:
    def __init__(self, db: Database, backend: Backend, chronicle: Chronicle) -> None:
        self.db = db
        self.backend = backend
        self.chronicle = chronicle

    def is_canary(self, key: str) -> bool:
        folded = key.casefold()
        return any(row["key"].casefold() == folded for row in self.db.all("SELECT key FROM canaries"))

    def plant(self, key: str, *, content: bytes | None = None, note: str = "") -> dict:
        """Register ``key`` as a canary, writing a decoy first if it does not exist."""
        key = normalize_key(key)
        created = self.backend.stat(key) is None
        if created:
            self.backend.write(key, content or DECOY.format(token=secrets.token_hex(16)).encode())
        checksum = self.backend.checksum(key)
        self.db.execute(
            "INSERT OR REPLACE INTO canaries (key, checksum, planted_at, note) VALUES (?, ?, ?, ?)",
            (key, checksum, now(), note or None),
        )
        self.chronicle.record("traps", "traps.planted", key=key, created=created, note=note)
        return {"key": key, "created": created, "checksum": checksum}

    def remove(self, key: str) -> bool:
        key = normalize_key(key)
        removed = self.db.execute("DELETE FROM canaries WHERE key = ?", (key,)).rowcount == 1
        if removed:
            self.chronicle.record("traps", "traps.removed", key=key)
        return removed

    def list(self) -> list[dict]:
        return [dict(r) for r in self.db.all("SELECT * FROM canaries ORDER BY key")]

    def inspect(self) -> list[dict]:
        """Canaries that are missing or were modified."""
        problems = []
        for canary in self.list():
            current = self.backend.checksum(canary["key"])
            if current is None:
                problems.append({"key": canary["key"], "problem": "missing"})
            elif current != canary["checksum"]:
                problems.append({"key": canary["key"], "problem": "modified"})
        return problems
