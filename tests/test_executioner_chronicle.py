"""The Executioner only strikes on a valid seal; the Chronicle notices tampering."""

from __future__ import annotations

import sqlite3
import time
import unittest
from unittest import mock

from redcastle.chronicle import Chronicle
from redcastle.executioner import ExecutionRefused
from redcastle.registry import Status
from redcastle.seal import royal_seal, seal_is_valid

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

    def test_a_mangled_warrant_is_no_warrant(self) -> None:
        good = royal_seal(b"key", "rc-1", "cell", "sha256:x")
        self.assertTrue(seal_is_valid(b"key", good, "rc-1", "cell", "sha256:x"))
        self.assertFalse(seal_is_valid(b"key", "sälj", "rc-1", "cell", "sha256:x"))
        self.assertFalse(seal_is_valid(b"key", b"\xff", "rc-1", "cell", "sha256:x"))
        self.assertFalse(seal_is_valid(b"key", good, "rc-1", None, "sha256:x"))

    def test_refuses_what_it_cannot_verify(self) -> None:
        case = self.quarantined()
        seal = royal_seal(self.castle.throne._seal_key, case["id"], case["quarantine_location"], case["checksum"])
        self.castle.registry.transition(case["id"], Status.QUARANTINED, Status.APPROVED, seal=seal)
        with mock.patch.object(self.castle.executioner.backend, "quarantined_checksum", side_effect=OSError("locked")):
            with self.assertRaises(ExecutionRefused):
                self.castle.executioner.execute(case["id"])
        self.assertTrue(self.castle.quarantine.intact(case["quarantine_location"], case["checksum"]))


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

    def test_a_row_of_the_wrong_kind_is_tampering_not_a_crash(self) -> None:
        conn = self.castle.db.conn
        conn.execute("DROP TRIGGER chronicle_no_update")
        conn.execute("UPDATE chronicle SET data = x'00ff' WHERE seq = 1")
        result = self.castle.chronicle.verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 1)

    def test_a_long_chain_is_verified_page_by_page(self) -> None:
        for i in range(7):
            self.castle.chronicle.record("test", "test.entry", i=i)
        with mock.patch("redcastle.chronicle.VERIFY_PAGE", 3):
            self.assertTrue(self.castle.chronicle.verify().ok)
            self.assertEqual(self.castle.chronicle.verify().entries, self.castle.chronicle.head()["seq"])
            conn = self.castle.db.conn
            conn.execute("DROP TRIGGER chronicle_no_update")
            conn.execute("UPDATE chronicle SET data = '{}' WHERE seq = 5")
            self.assertEqual(self.castle.chronicle.verify().broken_at, 5)

    def test_a_head_is_held_until_the_chronicle_loses_it(self) -> None:
        head = self.castle.chronicle.head()
        self.assertTrue(self.castle.chronicle.holds(head["seq"], head["hash"]))
        self.assertFalse(self.castle.chronicle.holds(head["seq"], "0" * 64))
        self.assertFalse(self.castle.chronicle.holds(head["seq"] + 1, head["hash"]))


class WatchtowerAlertTests(CastleTestCase):
    def test_short_commands_wait_for_their_webhooks(self) -> None:
        delivered = []

        def slow_endpoint(request: object, timeout: float) -> mock.MagicMock:
            time.sleep(0.2)
            delivered.append(request)
            return mock.MagicMock()

        self.castle.config.watchtower.webhook_url = "http://example.invalid/hook"
        with mock.patch("redcastle.watchtower.urllib.request.urlopen", side_effect=slow_endpoint):
            self.castle.watchtower.alert("critical", "test", "fire")
            self.castle.watchtower.close()
        self.assertEqual(len(delivered), 1)

    def test_the_horn_sounds_even_if_the_records_cannot_be_kept(self) -> None:
        with mock.patch.object(self.castle.watchtower.db, "execute", side_effect=sqlite3.OperationalError("disk full")):
            self.castle.watchtower.alert("critical", "test", "fire")
        self.assertEqual(self.notifications[0][1], "fire")


if __name__ == "__main__":
    unittest.main()
