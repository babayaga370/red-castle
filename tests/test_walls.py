"""Around the wall: the Moat, the Traps and the Watchtower."""

from __future__ import annotations

import unittest

from redcastle.registry import Status
from redcastle.storage import InvalidKey, make_backend

from .helpers import CastleTestCase


class MoatTests(CastleTestCase):
    def test_protected_patterns(self) -> None:
        self.put("keys/server.pem")
        self.put("repo/.git/config")
        self.assertEqual(self.ask("keys/server.pem")["reason_code"], "protected_object")
        self.assertEqual(self.ask("repo/.git/config")["reason_code"], "protected_object")
        self.assertTrue((self.realm / "keys/server.pem").exists())

    def test_keys_cannot_escape_the_realm(self) -> None:
        (self.root / "outside.txt").write_text("not yours")
        for key in ("../outside.txt", "a/../../outside.txt", "", "a//b"):
            self.assertEqual(self.ask(key)["reason_code"], "invalid_key", key)
        self.assertTrue((self.root / "outside.txt").exists())

    def test_castle_files_are_never_in_reach(self) -> None:
        # Even a realm configured as the castle's own folder must not expose it.
        self.castle.config.storage.realm = str(self.castle.config.root)
        backend = make_backend(self.castle.config)
        keys = [o.key for o in backend.list_objects()]
        self.assertFalse(any(k.startswith(".redcastle/") or k == "redcastle.toml" for k in keys))
        for key in ("redcastle.toml", ".redcastle/secrets.json", ".redcastle/castle.db"):
            with self.assertRaises(InvalidKey):
                backend.stat(key)

    def test_reason_and_score_are_required(self) -> None:
        self.put("a.txt")
        self.assertEqual(self.ask("a.txt", reason="meh")["reason_code"], "reason_required")
        self.assertEqual(self.ask("a.txt", score=150)["reason_code"], "invalid_risk_score")
        self.assertEqual(self.ask("a.txt", score="low")["reason_code"], "invalid_risk_score")
        self.assertEqual(self.ask("a.txt", score=True)["reason_code"], "invalid_risk_score")

    def test_rate_limit(self) -> None:
        self.castle.moat.config.max_requests_per_minute = 3
        for i in range(4):
            self.put(f"f{i}.txt")
        results = [self.ask(f"f{i}.txt")["status"] for i in range(4)]
        self.assertEqual(results[:3], [Status.QUARANTINED] * 3)
        self.assertEqual(results[3], Status.REJECTED)


class TrapTests(CastleTestCase):
    def test_canary_freezes_the_agent_without_revealing_itself(self) -> None:
        self.castle.traps.plant("backups/passwords.txt")
        view = self.ask("backups/passwords.txt")
        self.assertEqual(view["status"], Status.REJECTED)
        self.assertNotIn("canary", view["message"].lower())
        self.assertEqual(self.case(view["request_id"])["status"], Status.TRAPPED)
        self.assertEqual(self.agent_status(), "frozen")
        self.assertTrue((self.realm / "backups/passwords.txt").exists())
        self.assertIn("trap_sprung", [a["kind"] for a in self.castle.watchtower.alerts()])

    def test_canary_match_ignores_case_and_slashes(self) -> None:
        self.castle.traps.plant("Backups/Passwords.txt")
        self.ask("/backups\\passwords.TXT")
        self.assertEqual(self.agent_status(), "frozen")

    def test_existing_object_can_become_a_canary(self) -> None:
        self.put("real.txt", b"keep me")
        result = self.castle.traps.plant("real.txt")
        self.assertFalse(result["created"])
        self.assertEqual((self.realm / "real.txt").read_bytes(), b"keep me")


class WatchtowerTests(CastleTestCase):
    def test_repeated_underestimates_freeze_the_agent(self) -> None:
        for i in range(3):
            self.put(f"config/prod{i}.env")
            self.ask(f"config/prod{i}.env", score=0)
        self.assertEqual(self.agent_status(), "frozen")

    def test_repeated_moat_rejections_freeze_the_agent(self) -> None:
        for _ in range(5):
            self.ask("../escape.txt")
        self.assertEqual(self.agent_status(), "frozen")

    def test_missing_objects_do_not_count_as_moat_rejections(self) -> None:
        for i in range(6):
            self.ask(f"ghost{i}.txt")
        self.assertEqual(self.agent_status(), "active")

    def test_patrol_detects_canary_deleted_behind_the_castle(self) -> None:
        self.castle.traps.plant("bait.txt")
        self.assertTrue(self.castle.patrol()["ok"])
        (self.realm / "bait.txt").unlink()
        first = self.castle.patrol()
        self.assertFalse(first["ok"])
        self.assertEqual(first["new_alerts"], 1)
        second = self.castle.patrol()
        self.assertFalse(second["ok"])
        self.assertEqual(second["new_alerts"], 0)  # already reported

    def test_patrol_detects_tampered_quarantine(self) -> None:
        self.put("a.txt")
        view = self.ask("a.txt")
        location = self.case(view["request_id"])["quarantine_location"]
        (self.castle.config.quarantine_dir / location / "object").write_bytes(b"swapped")
        report = self.castle.patrol()
        self.assertEqual([p["kind"] for p in report["problems"]], ["quarantine_breach"])


if __name__ == "__main__":
    unittest.main()
