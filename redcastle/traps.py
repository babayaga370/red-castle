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
from .util import fold, now

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

    def _find(self, key: str) -> str | None:
        folded = fold(key)
        return next((r["key"] for r in self.db.all("SELECT key FROM canaries") if fold(r["key"]) == folded), None)

    def is_canary(self, key: str) -> bool:
        return self._find(key) is not None

    def plant(self, key: str, *, content: bytes | None = None, note: str = "") -> dict:
        """Register ``key`` as a canary, writing a decoy first if it does not exist."""
        key = self.backend.canonical_key(key)
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
        canary = self._find(normalize_key(key))
        if canary is None:
            return False
        self.db.execute("DELETE FROM canaries WHERE key = ?", (canary,))
        self.chronicle.record("traps", "traps.removed", key=canary)
        return True

    def list(self) -> list[dict]:
        return [dict(r) for r in self.db.all("SELECT * FROM canaries ORDER BY key")]

    def inspect(self) -> list[dict]:
        """Canaries that are missing, were modified, or could not be checked."""
        problems = []
        for canary in self.list():
            try:
                current = self.backend.checksum(canary["key"])
            except Exception as exc:  # noqa: BLE001 - swapped for a link, say, or the storage is down
                problems.append({"key": canary["key"], "problem": "unreadable", "error": str(exc)})
                continue
            if current is None:
                problems.append({"key": canary["key"], "problem": "missing"})
            elif current != canary["checksum"]:
                problems.append({"key": canary["key"], "problem": "modified"})
        return problems
