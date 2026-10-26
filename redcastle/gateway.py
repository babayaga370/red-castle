"""The Gateway: the only door agents can knock on. It accepts requests; it never deletes."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .moat import MoatViolation
from .registry import Status
from .storage import InvalidKey, ObjectNotFound
from .util import iso

if TYPE_CHECKING:
    from .castle import Castle

log = logging.getLogger("redcastle.gateway")

AGENT_MESSAGES = {
    Status.RECEIVED: "The request is being processed.",
    Status.QUARANTINED: "The object is hidden in quarantine and awaits a human decision in the Throne Room.",
    Status.APPROVED: "A human approved the deletion; the Executioner will carry it out.",
    Status.EXECUTED: "The object was permanently deleted by the Executioner.",
    Status.RESTORED: "A human declined the deletion and restored the object.",
}
TRAPPED_MESSAGE = "Request denied. This agent has been frozen pending review in the Throne Room."


class GatewayError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def agent_view(case: dict) -> dict:
    """What an agent may know about its own request.

    A sprung trap is reported as a plain rejection, so agents cannot learn
    which objects are canaries.
    """
    status = case["status"]
    view = {
        "request_id": case["id"],
        "object_key": case["object_key"],
        "status": status,
        "message": AGENT_MESSAGES.get(status) or case["status_reason"],
        "your_risk_score": case["agent_score"],
        "created_at": iso(case["created_at"]),
        "updated_at": iso(case["updated_at"]),
    }
    if status == Status.TRAPPED:
        view["status"] = Status.REJECTED
        view["message"] = TRAPPED_MESSAGE
    elif status == Status.REJECTED:
        view["reason_code"] = case["status_code"]
    if case["judge_score"] is not None and status != Status.TRAPPED:
        view["judge"] = {
            "risk_score": case["judge_score"],
            "risk_level": case["judge_level"],
            "assessment": case["flag"] or "consistent",
        }
    return view


def _text(value: object, limit: int) -> str:
    return (value if isinstance(value, str) else repr(value))[:limit]


def _score(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 100:
        return None
    return int(round(value))


class Gateway:
    def __init__(self, castle: Castle) -> None:
        self.registry = castle.registry
        self.chronicle = castle.chronicle
        self.moat = castle.moat
        self.traps = castle.traps
        self.judge = castle.judge
        self.quarantine = castle.quarantine
        self.watchtower = castle.watchtower
        self.backend = castle.backend

    def authenticate(self, token: str | None) -> dict:
        if not token or not isinstance(token, str):
            raise GatewayError("unauthorized", "An agent token is required.", 401)
        agent = self.registry.agent_by_token(token)
        if agent is None:
            raise GatewayError("unauthorized", "Unknown agent token.", 401)
        return agent

    def list_objects(self, token: str | None, prefix: str = "", limit: int = 1000) -> dict:
        self.authenticate(token)
        objects = self.backend.list_objects(prefix or "")
        return {
            "prefix": prefix or "",
            "objects": [o.to_dict() for o in objects[:limit]],
            "truncated": len(objects) > limit,
        }

    def request_deletion(self, token: str | None, object_key: object, reason: object, risk_score: object) -> dict:
        agent = self.authenticate(token)
        name = agent["name"]
        request_id = self.registry.create_request(
            name, _text(object_key, 1024), _text(reason, 2000) if reason is not None else "", _score(risk_score)
        )
        self.chronicle.record(
            f"agent:{name}", "gateway.received",
            request_id=request_id, key=_text(object_key, 1024), reason=reason, agent_risk_score=risk_score,
        )

        # 1. The Moat (and the Traps hidden in it)
        try:
            self.moat.check_agent(agent)
            key, agent_score = self.moat.check_form(object_key, reason, risk_score)
            self.registry.update_request(request_id, object_key=key)
            if self.traps.is_canary(key):
                return self._spring_trap(name, request_id, key)
            self.moat.check_limits(name, key)
            info = self.backend.stat(key)
        except MoatViolation as violation:
            return self._reject(name, request_id, violation.code, str(violation), by="moat")
        except InvalidKey as exc:
            return self._reject(name, request_id, "invalid_key", str(exc), by="moat")
        if info is None:
            return self._reject(
                name, request_id, "object_not_found", f"No object named '{key}' exists.", by="gateway"
            )

        # 2. The Judge
        verdict = self.judge.evaluate(agent=name, key=key, reason=reason, agent_score=agent_score, info=info)
        self.registry.update_request(
            request_id, judge_score=verdict.score, judge_level=verdict.level, judge_factors=verdict.factors,
            discrepancy=verdict.discrepancy, flag=verdict.flag, size=info.size,
        )
        self.chronicle.record("judge", "judge.verdict", request_id=request_id, **verdict.to_dict())
        self.watchtower.note_verdict(name, request_id, verdict)

        # 3. The Quarantine
        try:
            location, checksum = self.quarantine.hide(request_id, key)
        except ObjectNotFound:
            return self._reject(
                name, request_id, "object_not_found", f"No object named '{key}' exists.", by="gateway"
            )
        except Exception as exc:  # noqa: BLE001 - any storage failure leaves the object where it was
            log.exception("Could not quarantine %s", key)
            self.registry.transition(
                request_id, Status.RECEIVED, Status.FAILED, status_code="storage_error",
                status_reason="The castle could not quarantine the object. Nothing was deleted.",
            )
            self.chronicle.record("quarantine", "quarantine.failed", request_id=request_id, error=str(exc))
            self.watchtower.alert(
                "critical", "quarantine_failed", f"Could not quarantine '{key}' (request {request_id}): {exc}",
                agent=name, request_id=request_id,
            )
            return self._view(request_id)
        self.registry.transition(
            request_id, Status.RECEIVED, Status.QUARANTINED, quarantine_location=location, checksum=checksum
        )
        self.watchtower.note_quarantined(self.registry.get_request(request_id))
        return self._view(request_id)

    def get_request(self, token: str | None, request_id: str) -> dict:
        agent = self.authenticate(token)
        case = self.registry.get_request(request_id)
        if case is None or case["agent"] != agent["name"]:
            raise GatewayError("not_found", f"You have no request {request_id}.", 404)
        return agent_view(case)

    def list_requests(self, token: str | None, status: str | None = None, limit: int = 100) -> list[dict]:
        agent = self.authenticate(token)
        if status and status not in Status.ALL:
            raise GatewayError("bad_request", f"Unknown status '{status}'.", 400)
        statuses = (Status.REJECTED, Status.TRAPPED) if status == Status.REJECTED else status
        cases = self.registry.list_requests(status=statuses, agent=agent["name"], limit=limit)
        return [agent_view(c) for c in cases]

    # -- outcomes -------------------------------------------------------------

    def _view(self, request_id: str) -> dict:
        return agent_view(self.registry.get_request(request_id))

    def _reject(self, agent: str, request_id: str, code: str, message: str, *, by: str) -> dict:
        self.registry.transition(
            request_id, Status.RECEIVED, Status.REJECTED, status_code=code, status_reason=message, rejected_by=by
        )
        self.chronicle.record(by, f"{by}.rejected", request_id=request_id, agent=agent, code=code, reason=message)
        if by == "moat":
            self.watchtower.note_rejection(agent, request_id, code)
        return self._view(request_id)

    def _spring_trap(self, agent: str, request_id: str, key: str) -> dict:
        self.registry.transition(
            request_id, Status.RECEIVED, Status.TRAPPED, status_code="trap",
            status_reason=f"Requested deletion of the canary '{key}'.", rejected_by="traps",
        )
        self.chronicle.record("traps", "traps.sprung", request_id=request_id, agent=agent, key=key)
        self.watchtower.trap_sprung(agent, request_id, key)
        return self._view(request_id)
