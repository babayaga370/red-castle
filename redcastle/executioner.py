"""The Executioner: the only role in the world authorized to permanently delete.

It holds the only backend handle that is allowed to purge, and it acts only on
cases the Throne Room approved and sealed. Before it strikes it verifies the
seal and that the quarantined object is exactly the one the human approved.
"""

from __future__ import annotations

from .chronicle import Chronicle
from .registry import Registry, Status
from .seal import seal_is_valid
from .storage import Backend
from .util import now
from .watchtower import Watchtower


class ExecutionRefused(Exception):
    pass


class Executioner:
    def __init__(
        self,
        registry: Registry,
        backend: Backend,
        chronicle: Chronicle,
        watchtower: Watchtower,
        seal_key: bytes,
    ) -> None:
        self.registry = registry
        self.backend = backend
        self.chronicle = chronicle
        self.watchtower = watchtower
        self._seal_key = seal_key

    def execute(self, request_id: str) -> dict:
        case = self.registry.get_request(request_id)
        if case is None:
            raise ExecutionRefused(f"There is no case {request_id}.")
        if case["status"] != Status.APPROVED:
            raise self._refuse(case, f"the case is '{case['status']}', not approved", alarm=False)
        location, checksum = case["quarantine_location"], case["checksum"]
        if not seal_is_valid(self._seal_key, case["seal"], case["id"], location, checksum):
            raise self._refuse(case, "the royal seal is missing or forged", alarm=True)
        current = self.backend.quarantined_checksum(location)
        if current is None:
            raise self._refuse(case, "the object is no longer in quarantine", alarm=True)
        if current != checksum:
            raise self._refuse(case, "the quarantined object changed after it was judged", alarm=True)
        try:
            self.backend.purge(location)
        except Exception as exc:  # noqa: BLE001 - report every failure the same way
            raise self._refuse(case, f"the purge failed: {exc}", alarm=True) from exc
        self.registry.transition(
            request_id, Status.APPROVED, Status.EXECUTED, executed_at=now(), status_reason=None
        )
        self.chronicle.record(
            "executioner", "executioner.executed",
            request_id=request_id, key=case["object_key"], checksum=checksum, approved_by=case["decided_by"],
        )
        return self.registry.get_request(request_id)

    def run_pending(self) -> list[tuple[str, str]]:
        """Carry out every approved case that has not been executed yet."""
        results = []
        for case in self.registry.list_requests(status=Status.APPROVED, oldest_first=True):
            try:
                self.execute(case["id"])
                results.append((case["id"], "executed"))
            except ExecutionRefused as exc:
                results.append((case["id"], f"refused: {exc}"))
        return results

    def _refuse(self, case: dict, reason: str, *, alarm: bool) -> ExecutionRefused:
        if case["status"] == Status.APPROVED:
            self.registry.update_request(case["id"], status_reason=f"The Executioner refused: {reason}.")
        self.chronicle.record("executioner", "executioner.refused", request_id=case["id"], reason=reason)
        if alarm:
            self.watchtower.alert(
                "critical", "execution_refused", f"The Executioner refused case {case['id']}: {reason}.",
                agent=case["agent"], request_id=case["id"],
            )
        return ExecutionRefused(reason)
