"""The Watchtower: monitoring, alerts and automatic freezes."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import urllib.request
from typing import TYPE_CHECKING, Any

from .chronicle import Chronicle
from .config import WatchtowerConfig
from .db import Database
from .notify import Notifier
from .registry import Registry, Status
from .util import iso, now

if TYPE_CHECKING:
    from .judge import Verdict
    from .storage import Backend
    from .traps import Traps

log = logging.getLogger("redcastle.watchtower")
_LOG_LEVELS = {"info": logging.INFO, "warning": logging.WARNING, "critical": logging.CRITICAL}
_HELD = (Status.QUARANTINED, Status.APPROVED)  # the statuses whose object sits in quarantine


class Watchtower:
    def __init__(
        self,
        db: Database,
        registry: Registry,
        chronicle: Chronicle,
        config: WatchtowerConfig,
        notifier: Notifier,
    ) -> None:
        self.db = db
        self.registry = registry
        self.chronicle = chronicle
        self.config = config
        self.notifier = notifier
        self._open_problems: set[str] = set()
        self._chronicle_peak = 0
        self._deliveries: list[threading.Thread] = []

    # -- alerts ---------------------------------------------------------------

    def alert(
        self,
        severity: str,
        kind: str,
        message: str,
        *,
        agent: str | None = None,
        notify: bool = True,
        **data: Any,
    ) -> dict:
        ts = now()
        log.log(_LOG_LEVELS.get(severity, logging.WARNING), "[%s] %s", kind, message)
        alert_id = None
        try:
            alert_id = self.db.execute(
                "INSERT INTO alerts (ts, severity, kind, agent, message, data) VALUES (?, ?, ?, ?, ?, ?)",
                (ts, severity, kind, agent, message, json.dumps(data, default=str, sort_keys=True)),
            ).lastrowid
            self.chronicle.record(
                "watchtower", "watchtower.alert", severity=severity, kind=kind, agent=agent, message=message, **data
            )
        except sqlite3.Error:  # the horn must sound even if the records cannot be kept
            log.exception("Could not record the alert")
        alert = {
            "id": alert_id, "ts": iso(ts), "severity": severity, "kind": kind,
            "agent": agent, "message": message, "data": data,
        }
        if self.config.webhook_url and severity != "info":
            thread = threading.Thread(target=self._post_webhook, args=(alert,), daemon=True)
            self._deliveries.append(thread)
            thread.start()
        if notify:
            self.notifier.alert(severity, message)
        return alert

    def _post_webhook(self, alert: dict) -> None:
        body = json.dumps({"source": "red-castle", **alert}, default=str).encode("utf-8", "backslashreplace")
        request = urllib.request.Request(
            self.config.webhook_url, data=body, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            urllib.request.urlopen(request, timeout=10).close()
        except Exception as exc:  # noqa: BLE001 - a failed webhook must never break the castle
            log.warning("Webhook delivery failed: %s", exc)
        finally:
            self._deliveries.remove(threading.current_thread())

    def close(self, timeout: float = 15) -> None:
        """Wait for webhooks under way: a short-lived command must not swallow its alerts."""
        deadline = time.monotonic() + timeout
        for thread in list(self._deliveries):
            thread.join(max(0, deadline - time.monotonic()))

    def alerts(self, limit: int = 50) -> list[dict]:
        rows = self.db.all("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        return [{**dict(r), "ts": iso(r["ts"]), "data": json.loads(r["data"] or "{}")} for r in rows]

    # -- reactions to what the Gateway sees --------------------------------------

    def freeze(self, agent: str, reason: str) -> bool:
        """Freeze an agent automatically. False if it was already frozen."""
        if not self.registry.freeze_agent(agent, by="watchtower", reason=reason):
            return False
        self.chronicle.record("watchtower", "watchtower.froze_agent", agent=agent, reason=reason)
        self.alert("critical", "agent_frozen", f"Agent '{agent}' was frozen automatically: {reason}.", agent=agent)
        return True

    def trap_sprung(self, agent: str, request_id: str, key: str) -> None:
        self.alert(
            "critical", "trap_sprung", f"Agent '{agent}' asked to delete the canary '{key}'.",
            agent=agent, request_id=request_id, key=key,
        )
        self.freeze(agent, f"requested deletion of a canary object (request {request_id})")

    def note_rejection(self, agent: str, request_id: str, code: str) -> None:
        window = self.config.rejection_window_minutes
        count = self.registry.count_rejections(agent, now() - window * 60)
        if count >= self.config.rejection_limit:
            self.freeze(agent, f"{count} requests rejected by the Moat within {window} minutes")

    def note_verdict(self, agent: str, request_id: str, verdict: Verdict) -> None:
        if verdict.flag != "underestimated":
            return
        # No notification of its own: the "awaiting judgement" notice carries the flag.
        self.alert(
            "warning", "risk_underestimated",
            f"Agent '{agent}' rated request {request_id} at {verdict.agent_score}; the Judge says {verdict.score}.",
            agent=agent, request_id=request_id, notify=False,
        )
        window = self.config.underestimate_window_minutes
        count = self.registry.count_flags(agent, "underestimated", now() - window * 60)
        if count >= self.config.underestimate_limit:
            self.freeze(agent, f"underestimated the risk {count} times within {window} minutes")

    def note_quarantined(self, case: dict) -> None:
        """An object now waits for a human - let them know."""
        self.notifier.awaiting(case)

    # -- patrol ---------------------------------------------------------------

    def patrol(self, traps: Traps, backend: Backend) -> dict:
        """Check the Chronicle, every canary and every quarantined object.

        Raises one alert per new problem; problems already reported on the
        previous patrol are not reported again. Also reminds the human about
        cases that have waited too long. Something that cannot be checked is a
        problem in itself: it must never stop the rest of the patrol.
        """
        problems: list[dict] = []
        verification = self.chronicle.verify()
        if not verification.ok:
            problems.append({
                "id": "chronicle",
                "kind": "chronicle_tampered",
                "message": f"The Chronicle fails verification at entry {verification.broken_at}: "
                           f"{verification.problem}.",
            })
        elif verification.entries < self._chronicle_peak:
            problems.append({
                "id": "chronicle:shrank",
                "kind": "chronicle_tampered",
                "message": f"The Chronicle shrank from {self._chronicle_peak} to {verification.entries} entries.",
            })
        self._chronicle_peak = max(self._chronicle_peak, verification.entries)
        for issue in traps.inspect():
            problems.append({
                "id": f"canary:{issue['key']}:{issue['problem']}",
                "kind": "canary_disturbed",
                "message": f"Canary '{issue['key']}' could not be checked: {issue['error']}." if "error" in issue else
                           f"Canary '{issue['key']}' is {issue['problem']} - something touched it "
                           "without going through the Gateway.",
            })
        held = self.registry.list_requests(status=_HELD, limit=1_000_000)
        for case in held:
            try:
                current = backend.quarantined_checksum(case["quarantine_location"])
            except Exception as exc:  # noqa: BLE001 - locked by another program, say, or the storage is down
                problems.append({
                    "id": f"quarantine:{case['id']}:unreadable",
                    "kind": "quarantine_unreadable",
                    "message": f"The quarantined object of case {case['id']} ('{case['object_key']}') "
                               f"could not be checked: {exc}.",
                })
                continue
            # A human may have decided the case from the terminal since we listed it.
            if current != case["checksum"] and self.registry.get_request(case["id"])["status"] in _HELD:
                state = "missing" if current is None else "altered"
                problems.append({
                    "id": f"quarantine:{case['id']}:{state}",
                    "kind": "quarantine_breach",
                    "message": f"The quarantined object of case {case['id']} ('{case['object_key']}') is {state}.",
                })
        fresh = [p for p in problems if p["id"] not in self._open_problems]
        for problem in fresh:
            self.alert("critical", problem["kind"], problem["message"])
        self._open_problems = {p["id"] for p in problems}
        self.notifier.remind([c for c in held if c["status"] == Status.QUARANTINED])
        return {
            "ok": not problems,
            "chronicle_entries": verification.entries,
            "canaries": len(traps.list()),
            "quarantined": len(held),
            "problems": problems,
            "new_alerts": len(fresh),
        }

    def status(self) -> dict:
        t = now()
        agents = [
            {
                "name": a["name"],
                "status": a["status"],
                "frozen_reason": a["frozen_reason"],
                "requests_24h": self.registry.count_requests(a["name"], t - 86400),
                "rejections_24h": self.registry.count_rejections(a["name"], t - 86400),
                "underestimates_7d": self.registry.count_flags(a["name"], "underestimated", t - 7 * 86400),
            }
            for a in self.registry.list_agents()
        ]
        return {
            "agents": agents,
            "cases": self.registry.status_counts(),
            "alerts": self.alerts(10),
            "chronicle_head": self.chronicle.head(),
        }
