"""The castle's records: registered agents and their deletion requests (cases)."""

from __future__ import annotations

import json
import re
import secrets
import uuid
from collections.abc import Sequence
from typing import Any

from .db import Database
from .util import hash_token, now


class Status:
    RECEIVED = "received"        # the Gateway has it, nothing decided yet
    REJECTED = "rejected"        # stopped by the Moat or the Gateway
    TRAPPED = "trapped"          # the agent reached for a canary
    QUARANTINED = "quarantined"  # hidden, waiting for the Throne Room
    APPROVED = "approved"        # sealed by a human, waiting for the Executioner
    EXECUTED = "executed"        # permanently deleted
    RESTORED = "restored"        # a human brought it back
    FAILED = "failed"            # storage error; nothing was deleted

    ALL = (RECEIVED, REJECTED, TRAPPED, QUARANTINED, APPROVED, EXECUTED, RESTORED, FAILED)


AGENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

REQUEST_COLUMNS = frozenset({
    "object_key", "agent_score", "judge_score", "judge_level", "judge_factors",
    "discrepancy", "flag", "status", "status_code", "status_reason", "rejected_by",
    "quarantine_location", "checksum", "size", "seal", "decided_by", "decided_at",
    "decision_note", "executed_at",
})


def _new_token() -> str:
    return "rc_agent_" + secrets.token_urlsafe(32)


def _request(row: Any) -> dict:
    case = dict(row)
    if case.get("judge_factors"):
        case["judge_factors"] = json.loads(case["judge_factors"])
    return case


class Registry:
    def __init__(self, db: Database) -> None:
        self.db = db

    # -- agents ---------------------------------------------------------------

    def add_agent(self, name: str) -> str:
        """Register an agent and return its token (only its hash is stored)."""
        if not AGENT_NAME.fullmatch(name):
            raise ValueError(
                "Agent names may contain letters, digits, '.', '_' and '-' (max 64 characters)."
            )
        if self.get_agent(name):
            raise ValueError(f"Agent '{name}' already exists.")
        token = _new_token()
        self.db.execute(
            "INSERT INTO agents (name, token_hash, status, created_at) VALUES (?, ?, 'active', ?)",
            (name, hash_token(token), now()),
        )
        return token

    def rotate_token(self, name: str) -> str | None:
        """Give an agent a new token; the old one stops working at once. None if there is no such agent."""
        token = _new_token()
        cur = self.db.execute("UPDATE agents SET token_hash = ? WHERE name = ?", (hash_token(token), name))
        return token if cur.rowcount == 1 else None

    def agent_by_token(self, token: str) -> dict | None:
        row = self.db.one("SELECT * FROM agents WHERE token_hash = ?", (hash_token(token),))
        return dict(row) if row else None

    def get_agent(self, name: str) -> dict | None:
        row = self.db.one("SELECT * FROM agents WHERE name = ?", (name,))
        return dict(row) if row else None

    def list_agents(self) -> list[dict]:
        return [dict(r) for r in self.db.all("SELECT * FROM agents ORDER BY name")]

    def freeze_agent(self, name: str, *, by: str, reason: str) -> bool:
        cur = self.db.execute(
            "UPDATE agents SET status = 'frozen', frozen_at = ?, frozen_by = ?, frozen_reason = ? "
            "WHERE name = ? AND status = 'active'",
            (now(), by, reason, name),
        )
        return cur.rowcount == 1

    def unfreeze_agent(self, name: str) -> bool:
        cur = self.db.execute(
            "UPDATE agents SET status = 'active', frozen_at = NULL, frozen_by = NULL, "
            "frozen_reason = NULL WHERE name = ? AND status = 'frozen'",
            (name,),
        )
        return cur.rowcount == 1

    # -- requests -------------------------------------------------------------

    def create_request(self, agent: str, object_key: str, reason: str, agent_score: int | None) -> str:
        request_id = "rc-" + uuid.uuid4().hex[:12]
        ts = now()
        self.db.execute(
            "INSERT INTO requests (id, agent, object_key, reason, agent_score, status, created_at, "
            "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (request_id, agent, object_key, reason, agent_score, Status.RECEIVED, ts, ts),
        )
        return request_id

    def update_request(self, request_id: str, **fields: Any) -> None:
        self._set(request_id, None, fields)

    def transition(self, request_id: str, from_status: str, to_status: str, **fields: Any) -> bool:
        """Move a case between statuses; False if it was no longer in ``from_status``."""
        fields["status"] = to_status
        return self._set(request_id, from_status, fields)

    def _set(self, request_id: str, expected_status: str | None, fields: dict[str, Any]) -> bool:
        unknown = set(fields) - REQUEST_COLUMNS
        if unknown:
            raise ValueError(f"Unknown request fields: {sorted(unknown)}")
        if isinstance(fields.get("judge_factors"), list):
            fields["judge_factors"] = json.dumps(fields["judge_factors"])
        fields["updated_at"] = now()
        sql = "UPDATE requests SET " + ", ".join(f"{name} = ?" for name in fields) + " WHERE id = ?"
        params = [*fields.values(), request_id]
        if expected_status is not None:
            sql += " AND status = ?"
            params.append(expected_status)
        return self.db.execute(sql, params).rowcount == 1

    def get_request(self, request_id: str) -> dict | None:
        row = self.db.one("SELECT * FROM requests WHERE id = ?", (request_id,))
        return _request(row) if row else None

    def list_requests(
        self,
        *,
        status: str | Sequence[str] | None = None,
        agent: str | None = None,
        limit: int = 200,
        oldest_first: bool = False,
    ) -> list[dict]:
        clauses, params = [], []
        if status:
            statuses = [status] if isinstance(status, str) else list(status)
            clauses.append(f"status IN ({', '.join('?' * len(statuses))})")
            params.extend(statuses)
        if agent:
            clauses.append("agent = ?")
            params.append(agent)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "ASC" if oldest_first else "DESC"
        rows = self.db.all(
            f"SELECT * FROM requests {where} ORDER BY created_at {order} LIMIT ?", [*params, limit]
        )
        return [_request(r) for r in rows]

    def count_requests(self, agent: str, since: float) -> int:
        row = self.db.one(
            "SELECT COUNT(*) FROM requests WHERE agent = ? AND created_at >= ?", (agent, since)
        )
        return row[0]

    def count_rejections(self, agent: str, since: float, *, by: str = "moat") -> int:
        row = self.db.one(
            "SELECT COUNT(*) FROM requests WHERE agent = ? AND rejected_by = ? AND created_at >= ?",
            (agent, by, since),
        )
        return row[0]

    def count_flags(self, agent: str, flag: str, since: float) -> int:
        row = self.db.one(
            "SELECT COUNT(*) FROM requests WHERE agent = ? AND flag = ? AND created_at >= ?",
            (agent, flag, since),
        )
        return row[0]

    def status_counts(self) -> dict[str, int]:
        rows = self.db.all("SELECT status, COUNT(*) AS n FROM requests GROUP BY status")
        return {r["status"]: r["n"] for r in rows}
