"""The Throne Room: a human approves, restores, or freezes the agent."""

from __future__ import annotations

from .chronicle import Chronicle
from .executioner import ExecutionRefused, Executioner
from .quarantine import Quarantine
from .registry import Registry, Status
from .seal import royal_seal
from .storage import InvalidKey, ObjectExists, ObjectNotFound, normalize_key
from .util import now


class ThroneError(Exception):
    def __init__(self, message: str, code: str = "conflict") -> None:
        super().__init__(message)
        self.code = code


def _who(by: object) -> str:
    if not isinstance(by, str) or not by.strip():
        raise ThroneError("Every decision needs the name of the human who makes it.", "bad_request")
    return by.strip()


class ThroneRoom:
    def __init__(
        self,
        registry: Registry,
        quarantine: Quarantine,
        executioner: Executioner,
        chronicle: Chronicle,
        seal_key: bytes,
    ) -> None:
        self.registry = registry
        self.quarantine = quarantine
        self.executioner = executioner
        self.chronicle = chronicle
        self._seal_key = seal_key

    def pending(self) -> list[dict]:
        return self.registry.list_requests(status=Status.QUARANTINED, oldest_first=True)

    def case(self, request_id: str) -> dict:
        case = self.registry.get_request(request_id)
        if case is None:
            raise ThroneError(f"There is no case {request_id}.", "not_found")
        return case

    def _quarantined(self, request_id: str, verb: str) -> dict:
        case = self.case(request_id)
        if case["status"] != Status.QUARANTINED:
            raise ThroneError(f"Case {request_id} is '{case['status']}'; only quarantined cases can be {verb}.")
        return case

    def approve(self, request_id: str, *, by: str, note: str = "") -> dict:
        """Seal a death warrant and hand it to the Executioner."""
        by = _who(by)
        case = self._quarantined(request_id, "approved")
        seal = royal_seal(self._seal_key, case["id"], case["quarantine_location"], case["checksum"])
        if not self.registry.transition(
            request_id, Status.QUARANTINED, Status.APPROVED,
            seal=seal, decided_by=by, decided_at=now(), decision_note=note or None,
        ):
            raise ThroneError(f"Case {request_id} changed while you were deciding; look again.")
        self.chronicle.record(
            f"human:{by}", "throne.approved",
            request_id=request_id, key=case["object_key"], agent=case["agent"],
            agent_risk_score=case["agent_score"], judge_risk_score=case["judge_score"], note=note,
        )
        try:
            return self.executioner.execute(request_id)
        except ExecutionRefused as exc:
            raise ThroneError(f"Approved, but the Executioner refused: {exc}.", "execution_refused") from exc

    def restore(self, request_id: str, *, by: str, note: str = "", target_key: str | None = None) -> dict:
        """Decline the deletion and put the object back (optionally under a new key)."""
        by = _who(by)
        case = self._quarantined(request_id, "restored")
        try:
            target = normalize_key(target_key) if target_key else case["object_key"]
            self.quarantine.release(request_id, case["quarantine_location"], target)
        except ObjectExists as exc:
            raise ThroneError(
                f"'{exc}' exists again; restore under another key (target_key / --as)."
            ) from exc
        except ObjectNotFound as exc:
            raise ThroneError(f"The quarantined object of case {request_id} is missing.") from exc
        except InvalidKey as exc:
            raise ThroneError(str(exc), "bad_request") from exc
        self.registry.transition(
            request_id, Status.QUARANTINED, Status.RESTORED,
            decided_by=by, decided_at=now(), decision_note=note or None,
            status_reason=f"Restored as '{target}'." if target != case["object_key"] else None,
        )
        self.chronicle.record(
            f"human:{by}", "throne.restored",
            request_id=request_id, key=case["object_key"], restored_as=target, agent=case["agent"], note=note,
        )
        return self.case(request_id)

    def freeze(self, agent: str, *, by: str, reason: str = "", restore_all: bool = False) -> dict:
        """Stop an agent from submitting requests; optionally restore everything it asked to delete."""
        by = _who(by)
        if self.registry.get_agent(agent) is None:
            raise ThroneError(f"There is no agent '{agent}'.", "not_found")
        changed = self.registry.freeze_agent(agent, by=f"human:{by}", reason=reason or "frozen by the Throne Room")
        if changed:
            self.chronicle.record(f"human:{by}", "throne.froze_agent", agent=agent, reason=reason)
        restored, failed = [], []
        if restore_all:
            for case in self.registry.list_requests(status=Status.QUARANTINED, agent=agent, limit=1_000_000):
                try:
                    self.restore(case["id"], by=by, note=f"agent frozen: {reason}")
                    restored.append(case["id"])
                except ThroneError as exc:
                    failed.append({"request_id": case["id"], "error": str(exc)})
        return {"agent": agent, "frozen": True, "was_already_frozen": not changed, "restored": restored, "failed": failed}

    def unfreeze(self, agent: str, *, by: str, note: str = "") -> dict:
        by = _who(by)
        if self.registry.get_agent(agent) is None:
            raise ThroneError(f"There is no agent '{agent}'.", "not_found")
        changed = self.registry.unfreeze_agent(agent)
        if changed:
            self.chronicle.record(f"human:{by}", "throne.unfroze_agent", agent=agent, note=note)
        return {"agent": agent, "frozen": False, "was_already_active": not changed}
