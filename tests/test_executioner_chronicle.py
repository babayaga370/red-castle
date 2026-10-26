"""The Executioner only strikes on a valid seal; the Chronicle notices tampering."""

from __future__ import annotations

import sqlite3
import unittest

from redcastle.chronicle import Chronicle
from redcastle.executioner import ExecutionRefused
from redcastle.registry import Status
from redcastle.seal import royal_seal

from .helpers import CastleTestCase


class ExecutionerTests(CastleTestCase):
    def quarantined(self, key: str = "a.txt") -> dict:
        self.put(key)
        return self.case(self.ask(key)["request_id"])

    def test_castle_storage_cannot_purge(self) -> None:
        case = self.quarantined()
        with self.assertRaises(PermissionError):
            self.castle.backend.purge(case["quarantine_location"])
        self.assertTrue(self.castle.quarantine.intact(case["quarantine_location"], case["checksum"]))

    def test_refuses_unapproved_case(self) -> None:
        case = self.quarantined()
        with self.assertRaises(ExecutionRefused):
            self.castle.executioner.execute(case["id"])
        self.assertEqual(self.case(case["id"])["status"], Status.QUARANTINED)

    def test_refuses_forged_seal(self) -> None:
        case = self.quarantined()
        self.castle.registry.transition(case["id"], Status.QUARANTINED, Status.APPROVED, seal="0" * 64)
        with self.assertRaises(ExecutionRefused):
            self.castle.executioner.execute(case["id"])
        self.assertTrue(self.castle.quarantine.intact(case["quarantine_location"], case["checksum"]))
        self.assertIn("execution_refused", [a["kind"] for a in self.castle.watchtower.alerts()])

    def test_refuses_object_swapped_after_judgement(self) -> None:
        case = self.quarantined()
        seal = royal_seal(self.castle.throne._seal_key, case["id"], case["quarantine_location"], case["checksum"])
        self.castle.registry.transition(case["id"], Status.QUARANTINED, Status.APPROVED, seal=seal)
        cell = self.castle.config.quarantine_dir / case["quarantine_location"] / "object"
        cell.write_bytes(b"something else")
        with self.assertRaises(ExecutionRefused):
            self.castle.executioner.execute(case["id"])
        self.assertTrue(cell.exists())

    def test_run_pending_executes_sealed_cases(self) -> None:
        case = self.quarantined()
        seal = royal_seal(self.castle.throne._seal_key, case["id"], case["quarantine_location"], case["checksum"])
        self.castle.registry.transition(case["id"], Status.QUARANTINED, Status.APPROVED, seal=seal)
        self.assertEqual(self.castle.executioner.run_pending(), [(case["id"], "executed")])


class ChronicleTests(CastleTestCase):
    def test_every_step_is_recorded_and_verifies(self) -> None:
        self.put("a.txt")
        view = self.ask("a.txt")
        self.castle.throne.approve(view["request_id"], by="alice")
        events = [e["event"] for e in reversed(self.castle.chronicle.entries(request_id=view["request_id"]))]
        self.assertEqual(
            events,
            ["gateway.received", "judge.verdict", "quarantine.hidden", "throne.approved", "executioner.executed"],
        )
        self.assertTrue(self.castle.chronicle.verify().ok)

    def test_entries_cannot_be_updated_or_deleted(self) -> None:
        conn = self.castle.db.conn
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("UPDATE chronicle SET actor = 'nobody' WHERE seq = 1")
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM chronicle WHERE seq = 1")

    def test_tampering_is_detected(self) -> None:
        self.put("a.txt")
        self.ask("a.txt")
        conn = self.castle.db.conn
        conn.execute("DROP TRIGGER chronicle_no_update")
        conn.execute("UPDATE chronicle SET data = '{}' WHERE seq = 2")
        result = self.castle.chronicle.verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 2)

    def test_removed_entry_is_detected(self) -> None:
        self.put("a.txt")
        self.ask("a.txt")
        conn = self.castle.db.conn
        conn.execute("DROP TRIGGER chronicle_no_delete")
        conn.execute("DELETE FROM chronicle WHERE seq = 3")
        result = self.castle.chronicle.verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 3)

    def test_wrong_key_does_not_verify(self) -> None:
        self.assertFalse(Chronicle(self.castle.db, b"not the key").verify().ok)


if __name__ == "__main__":
    unittest.main()
