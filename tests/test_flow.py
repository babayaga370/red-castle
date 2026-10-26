"""The main road through the castle: Gateway -> Judge -> Quarantine -> Throne Room -> Executioner."""

from __future__ import annotations

import unittest

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
