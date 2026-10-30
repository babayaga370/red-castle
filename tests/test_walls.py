"""Around the wall: the Moat, the Traps and the Watchtower."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from redcastle.gateway import GatewayError
from redcastle.registry import Status
from redcastle.storage import InvalidKey, make_backend
from redcastle.util import glob_match

from .helpers import CastleTestCase


class MoatTests(CastleTestCase):
    def test_protected_patterns(self) -> None:
        self.put("keys/server.pem")
        self.put("repo/.git/config")
        self.assertEqual(self.ask("keys/server.pem")["reason_code"], "protected_object")
        self.assertEqual(self.ask("repo/.git/config")["reason_code"], "protected_object")
        self.assertTrue((self.realm / "keys/server.pem").exists())
        self.put("worktree/.git")
        self.put("home/.aws/credentials")
        self.assertEqual(self.ask("worktree/.git")["reason_code"], "protected_object")
        self.assertEqual(self.ask("home/.aws/credentials")["reason_code"], "protected_object")

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

    def test_castle_files_are_out_of_reach_in_any_case(self) -> None:
        self.castle.config.storage.realm = str(self.castle.config.root)
        backend = make_backend(self.castle.config)
        for key in (".REDCASTLE/secrets.json", "RedCastle.TOML"):
            with self.assertRaises(InvalidKey):
                backend.stat(key)

    def test_keys_with_control_characters_or_broken_unicode_are_refused(self) -> None:
        for key in ("a\x9b1mb.txt", "a\x85b", "a\ud800b"):
            self.assertEqual(self.ask(key)["reason_code"], "invalid_key", ascii(key))

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

    def test_a_flooding_agent_stops_leaving_traces(self) -> None:
        self.castle.moat.config.max_requests_per_minute = 2
        for _ in range(4):
            self.ask("ghost.txt")
        before = self.castle.chronicle.head()["seq"]
        requests = len(self.castle.registry.list_requests())
        with self.assertRaises(GatewayError) as caught:
            self.ask("ghost.txt", reason="x" * 2000)
        self.assertEqual(caught.exception.http_status, 429)
        self.assertEqual(self.castle.chronicle.head()["seq"], before)
        self.assertEqual(len(self.castle.registry.list_requests()), requests)


class SpellingTests(CastleTestCase):
    """The Moat and the Traps judge the object, however the agent spells its name."""

    def test_policy_is_applied_to_the_canonical_name(self) -> None:
        self.put("keys/server.pem")
        with mock.patch.object(self.castle.backend, "canonical_key", return_value="keys/server.pem"):
            self.assertEqual(self.ask("keys/another-name")["reason_code"], "protected_object")
        self.assertTrue((self.realm / "keys/server.pem").exists())

    @unittest.skipUnless(os.name == "nt", "Windows ignores trailing dots and spaces in names")
    def test_trailing_dots_and_spaces_do_not_get_past_the_walls(self) -> None:
        self.put("keys/server.pem")
        for key in ("keys/server.pem.", "keys/server.pem ", "keys/server.pem. .", "keys./server.pem"):
            self.assertEqual(self.ask(key)["reason_code"], "protected_object", repr(key))
        self.castle.traps.plant("bait.txt")
        self.ask("bait.txt.")
        self.assertEqual(self.agent_status(), "frozen")
        self.assertTrue((self.realm / "bait.txt").exists())

    @unittest.skipUnless(os.name == "nt", "only Windows has 8.3 short names")
    def test_short_names_do_not_get_past_the_moat(self) -> None:
        import ctypes

        path = self.put("repo/.git/config")
        buffer = ctypes.create_unicode_buffer(600)
        ctypes.windll.kernel32.GetShortPathNameW(str(path.parent), buffer, 600)
        short = Path(buffer.value).name
        if short == ".git":
            self.skipTest("8.3 names are turned off on this volume")
        self.assertEqual(self.ask(f"repo/{short}/config")["reason_code"], "protected_object")
        self.assertTrue(path.exists())

    def test_a_link_to_a_protected_folder_is_no_way_around(self) -> None:
        path = self.put("repo/.git/config")
        try:
            (self.realm / "innocent").symlink_to(path.parent, target_is_directory=True)
        except OSError:
            self.skipTest("this account may not create links")
        self.assertEqual(self.ask("innocent/config")["reason_code"], "protected_object")
        self.assertTrue(path.exists())

    def test_look_alike_spellings_match_patterns(self) -> None:
        self.assertTrue(glob_match("ｓｅｃｒｅｔ.txt", "*secret*"))
        self.assertTrue(glob_match("SERVER.PEM", "*.pem"))


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

    def test_a_sprung_trap_reads_like_any_frozen_rejection(self) -> None:
        self.castle.traps.plant("bait.txt")
        trapped = self.ask("bait.txt")
        self.put("a.txt")
        frozen = self.ask("a.txt")
        self.assertEqual(set(trapped), set(frozen))
        for field in ("status", "message", "reason_code"):
            self.assertEqual(trapped[field], frozen[field], field)

    def test_agents_cannot_filter_on_sprung_traps(self) -> None:
        self.castle.traps.plant("bait.txt")
        self.ask("bait.txt")
        with self.assertRaises(GatewayError):
            self.gw.list_requests(self.token, status=Status.TRAPPED)
        self.assertEqual(len(self.gw.list_requests(self.token, status=Status.REJECTED)), 1)

    def test_removing_a_canary_ignores_case(self) -> None:
        self.castle.traps.plant("Bait.txt")
        self.assertTrue(self.castle.traps.remove("BAIT.TXT"))
        self.assertEqual(self.castle.traps.list(), [])
        self.assertFalse(self.castle.traps.remove("bait.txt"))


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

    def test_patrol_survives_what_it_cannot_check(self) -> None:
        self.put("a.txt")
        self.ask("a.txt")
        self.castle.traps.plant("bait.txt")
        with (
            mock.patch.object(self.castle.backend, "checksum", side_effect=PermissionError("locked")),
            mock.patch.object(self.castle.backend, "quarantined_checksum", side_effect=OSError("locked")),
        ):
            report = self.castle.patrol()
        self.assertEqual(sorted(p["kind"] for p in report["problems"]), ["canary_disturbed", "quarantine_unreadable"])
        self.assertEqual(report["new_alerts"], 2)

    def test_patrol_does_not_cry_wolf_about_a_case_just_decided(self) -> None:
        self.put("a.txt")
        request_id = self.ask("a.txt")["request_id"]

        def decided_from_another_terminal(location: str) -> None:
            self.castle.throne.approve(request_id, by="alice")

        with mock.patch.object(self.castle.backend, "quarantined_checksum", side_effect=decided_from_another_terminal):
            report = self.castle.patrol()
        self.assertEqual(report["problems"], [])

    def test_patrol_notices_a_shrinking_chronicle(self) -> None:
        self.assertTrue(self.castle.patrol()["ok"])
        conn = self.castle.db.conn
        conn.execute("DROP TRIGGER chronicle_no_delete")
        conn.execute("DELETE FROM chronicle WHERE seq = ?", (self.castle.chronicle.head()["seq"],))
        report = self.castle.patrol()
        self.assertEqual([p["kind"] for p in report["problems"]], ["chronicle_tampered"])


if __name__ == "__main__":
    unittest.main()
