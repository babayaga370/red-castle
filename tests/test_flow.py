"""The main road through the castle: Gateway -> Judge -> Quarantine -> Throne Room -> Executioner."""

from __future__ import annotations

import sqlite3
import unittest
from unittest import mock

from redcastle.gateway import GatewayError
from redcastle.registry import Status
from redcastle.throne import ThroneError

from .helpers import CastleTestCase


class GatewayTests(CastleTestCase):
    def test_request_hides_object_in_quarantine(self) -> None:
        path = self.put("notes/old.txt")
        view = self.ask("notes/old.txt")
        self.assertEqual(view["status"], Status.QUARANTINED)
        self.assertFalse(path.exists())
        keys = [o["key"] for o in self.gw.list_objects(self.token)["objects"]]
        self.assertNotIn("notes/old.txt", keys)
        case = self.case(view["request_id"])
        self.assertTrue(self.castle.quarantine.intact(case["quarantine_location"], case["checksum"]))

    def test_unknown_token_is_refused(self) -> None:
        with self.assertRaises(GatewayError) as ctx:
            self.gw.request_deletion("nope", "a.txt", "some long reason", 10)
        self.assertEqual(ctx.exception.http_status, 401)

    def test_missing_object_is_rejected(self) -> None:
        view = self.ask("does/not/exist.txt")
        self.assertEqual(view["status"], Status.REJECTED)
        self.assertEqual(view["reason_code"], "object_not_found")

    def test_agent_only_sees_its_own_requests(self) -> None:
        self.put("a.txt")
        view = self.ask("a.txt")
        other = self.castle.registry.add_agent("other")
        with self.assertRaises(GatewayError):
            self.gw.get_request(other, view["request_id"])
        self.assertEqual(self.gw.list_requests(other), [])
        self.assertEqual(len(self.gw.list_requests(self.token)), 1)

    def test_long_listings_come_in_pages(self) -> None:
        for i in range(5):
            self.put(f"f{i}.txt")
        first = self.gw.list_objects(self.token, limit=2)
        self.assertEqual([o["key"] for o in first["objects"]], ["f0.txt", "f1.txt"])
        self.assertTrue(first["truncated"])
        rest = self.gw.list_objects(self.token, limit=10, after=first["next_after"])
        self.assertEqual([o["key"] for o in rest["objects"]], ["f2.txt", "f3.txt", "f4.txt"])
        self.assertFalse(rest["truncated"])
        self.assertIsNone(rest["next_after"])


class FailureTests(CastleTestCase):
    """When something breaks half-way, no object may end up out of everyone's reach."""

    def cells(self) -> list:
        return list(self.castle.config.quarantine_dir.iterdir())

    def test_object_goes_back_when_it_cannot_be_fingerprinted(self) -> None:
        path = self.put("a.txt", b"precious")
        with mock.patch.object(self.castle.backend, "quarantined_checksum", side_effect=OSError("disk hiccup")):
            view = self.ask("a.txt")
        self.assertEqual(view["status"], Status.FAILED)
        self.assertEqual(path.read_bytes(), b"precious")
        self.assertEqual(self.cells(), [])

    def test_object_goes_back_when_the_chronicle_cannot_record_it(self) -> None:
        path = self.put("a.txt", b"precious")
        with mock.patch.object(self.castle.quarantine, "chronicle") as chronicle:
            chronicle.record.side_effect = sqlite3.OperationalError("disk full")
            view = self.ask("a.txt")
        self.assertEqual(view["status"], Status.FAILED)
        self.assertEqual(path.read_bytes(), b"precious")

    def test_an_object_that_cannot_be_put_back_still_reaches_the_human(self) -> None:
        self.put("a.txt", b"precious")
        with (
            mock.patch.object(self.castle.backend, "quarantined_checksum", side_effect=OSError("locked")),
            mock.patch.object(self.castle.backend, "unhide", side_effect=OSError("locked")),
        ):
            view = self.ask("a.txt")
        self.assertEqual(view["status"], Status.RECEIVED)
        self.assertIn("quarantine_failed", [a["kind"] for a in self.castle.watchtower.alerts()])
        self.gw.settle_interrupted(older_than=0)
        self.assertEqual(self.case(view["request_id"])["status"], Status.QUARANTINED)
        self.castle.throne.restore(view["request_id"], by="alice")
        self.assertEqual((self.realm / "a.txt").read_bytes(), b"precious")

    def test_a_failed_move_leaves_no_stray_copy(self) -> None:
        path = self.put("a.txt")
        with mock.patch("redcastle.storage.local.shutil.move", side_effect=PermissionError("in use")):
            view = self.ask("a.txt")
        self.assertEqual(view["status"], Status.FAILED)
        self.assertTrue(path.exists())
        self.assertEqual(self.cells(), [])

    def test_storage_failure_before_the_quarantine_is_reported(self) -> None:
        path = self.put("a.txt")
        with mock.patch.object(self.castle.backend, "stat", side_effect=RuntimeError("AccessDenied")):
            view = self.ask("a.txt")
        self.assertEqual(view["status"], Status.FAILED)
        self.assertTrue(path.exists())
        self.assertIn("quarantine_failed", [a["kind"] for a in self.castle.watchtower.alerts()])

    def test_broken_unicode_in_a_reason_is_stored_cleanly(self) -> None:
        self.put("a.txt")
        view = self.ask("a.txt", reason="Superseded \ud800 by the new report")
        self.assertEqual(view["status"], Status.QUARANTINED)
        self.assertTrue(self.castle.chronicle.verify().ok)

    def test_invalid_scores_stay_out_of_the_chronicle(self) -> None:
        self.ask("a.txt", score=float("nan"))
        entry = self.castle.chronicle.entries(1000)[-2]
        self.assertEqual(entry["event"], "gateway.received")
        self.assertIsNone(entry["data"]["agent_risk_score"])
        self.assertNotIn("NaN", self.castle.db.one("SELECT data FROM chronicle WHERE seq = ?", (entry["seq"],))["data"])

    def test_a_long_reason_is_cut_short_in_the_chronicle_too(self) -> None:
        self.ask("a.txt", reason="x" * 50_000)
        entry = self.castle.chronicle.entries(1000)[-2]
        self.assertEqual(len(entry["data"]["reason"]), 2000)


class InterruptedRequestTests(CastleTestCase):
    """A crash can leave a request 'received', with its object already hidden in a cell."""

    def interrupted(self, *, hidden: bool) -> str:
        self.put("a.txt")
        request_id = self.castle.registry.create_request("tester", "a.txt", "cut short by a crash", 10)
        if hidden:
            self.castle.backend.hide("a.txt", request_id)
        return request_id

    def test_a_hidden_object_is_brought_before_the_human(self) -> None:
        request_id = self.interrupted(hidden=True)
        self.assertEqual(self.gw.settle_interrupted(older_than=0), [request_id])
        self.assertEqual(self.case(request_id)["status"], Status.QUARANTINED)
        self.assertEqual(len(self.notifications), 1)
        self.castle.throne.restore(request_id, by="alice")
        self.assertTrue((self.realm / "a.txt").exists())

    def test_a_request_that_hid_nothing_just_fails(self) -> None:
        request_id = self.interrupted(hidden=False)
        self.gw.settle_interrupted(older_than=0)
        self.assertEqual(self.case(request_id)["status"], Status.FAILED)
        self.assertTrue((self.realm / "a.txt").exists())

    def test_a_request_that_never_got_past_the_moat_just_fails(self) -> None:
        request_id = self.castle.registry.create_request("tester", "../escape", "cut short by a crash", 10)
        self.gw.settle_interrupted(older_than=0)
        self.assertEqual(self.case(request_id)["status"], Status.FAILED)

    def test_a_request_in_progress_is_left_alone(self) -> None:
        request_id = self.interrupted(hidden=True)
        self.castle.patrol()
        self.assertEqual(self.case(request_id)["status"], Status.RECEIVED)


class ThroneTests(CastleTestCase):
    def test_approve_executes_permanently(self) -> None:
        self.put("old.log")
        view = self.ask("old.log")
        location = self.case(view["request_id"])["quarantine_location"]
        case = self.castle.throne.approve(view["request_id"], by="alice")
        self.assertEqual(case["status"], Status.EXECUTED)
        self.assertEqual(case["decided_by"], "alice")
        self.assertIsNone(self.castle.backend.quarantined_checksum(location))
        self.assertFalse((self.realm / "old.log").exists())
        self.assertEqual(self.gw.get_request(self.token, view["request_id"])["status"], Status.EXECUTED)

    def test_restore_brings_object_back(self) -> None:
        path = self.put("report.docx", b"numbers")
        view = self.ask("report.docx")
        case = self.castle.throne.restore(view["request_id"], by="alice", note="still needed")
        self.assertEqual(case["status"], Status.RESTORED)
        self.assertEqual(path.read_bytes(), b"numbers")

    def test_restore_conflict_and_restore_under_new_key(self) -> None:
        self.put("a.txt", b"original")
        view = self.ask("a.txt")
        self.put("a.txt", b"newcomer")
        with self.assertRaises(ThroneError):
            self.castle.throne.restore(view["request_id"], by="alice")
        self.castle.throne.restore(view["request_id"], by="alice", target_key="a.restored.txt")
        self.assertEqual((self.realm / "a.restored.txt").read_bytes(), b"original")
        self.assertEqual((self.realm / "a.txt").read_bytes(), b"newcomer")

    def test_a_refused_execution_can_still_be_restored(self) -> None:
        self.put("a.txt")
        view = self.ask("a.txt")
        location = self.case(view["request_id"])["quarantine_location"]
        (self.castle.config.quarantine_dir / location / "object").write_bytes(b"swapped")
        with self.assertRaises(ThroneError):
            self.castle.throne.approve(view["request_id"], by="alice")
        self.assertEqual(self.case(view["request_id"])["status"], Status.APPROVED)
        case = self.castle.throne.restore(view["request_id"], by="alice", note="let me look at this first")
        self.assertEqual(case["status"], Status.RESTORED)
        self.assertIsNone(case["seal"])
        self.assertTrue((self.realm / "a.txt").exists())

    def test_a_failed_restore_is_a_throne_error(self) -> None:
        self.put("a/b.txt")
        view = self.ask("a/b.txt")
        (self.realm / "a").rmdir()
        (self.realm / "a").write_text("a file now")
        with self.assertRaises(ThroneError):
            self.castle.throne.restore(view["request_id"], by="alice")
        self.assertEqual(self.case(view["request_id"])["status"], Status.QUARANTINED)

    def test_decisions_need_a_name_and_a_quarantined_case(self) -> None:
        self.put("a.txt")
        view = self.ask("a.txt")
        with self.assertRaises(ThroneError):
            self.castle.throne.approve(view["request_id"], by="  ")
        self.castle.throne.approve(view["request_id"], by="alice")
        with self.assertRaises(ThroneError):
            self.castle.throne.approve(view["request_id"], by="alice")
        with self.assertRaises(ThroneError):
            self.castle.throne.restore(view["request_id"], by="alice")

    def test_freeze_with_restore_all(self) -> None:
        self.put("a.txt")
        self.put("b.txt")
        self.ask("a.txt")
        self.ask("b.txt")
        result = self.castle.throne.freeze("tester", by="alice", reason="too eager", restore_all=True)
        self.assertEqual(len(result["restored"]), 2)
        self.assertTrue((self.realm / "a.txt").exists() and (self.realm / "b.txt").exists())
        self.assertEqual(self.agent_status(), "frozen")
        self.put("c.txt")
        self.assertEqual(self.ask("c.txt")["reason_code"], "agent_frozen")
        self.castle.throne.unfreeze("tester", by="alice")
        self.assertEqual(self.ask("c.txt")["status"], Status.QUARANTINED)


class JudgeTests(CastleTestCase):
    def test_sensitive_objects_score_higher_than_junk(self) -> None:
        self.put("cache/build.tmp")
        self.put("config/prod-secrets.env")
        junk = self.ask("cache/build.tmp", score=0)
        secret = self.ask("config/prod-secrets.env", score=90)
        self.assertLess(junk["judge"]["risk_score"], secret["judge"]["risk_score"])
        self.assertEqual(secret["judge"]["risk_level"], "critical")

    def test_underestimate_is_flagged(self) -> None:
        self.put("config/prod.env")
        view = self.ask("config/prod.env", score=0)
        self.assertEqual(view["judge"]["assessment"], "underestimated")
        self.assertEqual(self.case(view["request_id"])["flag"], "underestimated")
        kinds = [a["kind"] for a in self.castle.watchtower.alerts()]
        self.assertIn("risk_underestimated", kinds)

    def test_recently_modified_objects_are_riskier(self) -> None:
        self.put("old.txt")
        self.put("fresh.txt", age=60)
        old = self.ask("old.txt")
        fresh = self.ask("fresh.txt")
        self.assertGreater(fresh["judge"]["risk_score"], old["judge"]["risk_score"])


if __name__ == "__main__":
    unittest.main()
