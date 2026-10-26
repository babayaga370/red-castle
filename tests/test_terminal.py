"""Working from the terminal: the review loop, status, and the background server's lifecycle."""

from __future__ import annotations

import contextlib
import io
import os
import threading
import time
import unittest
from unittest import mock

from redcastle import cli, daemon
from redcastle.api import serve
from redcastle.registry import Status

from .helpers import CastleTestCase


class ReviewTests(CastleTestCase):
    def run_cli(self, *argv: str, answers: list = ()) -> tuple[int, str]:
        out = io.StringIO()
        with mock.patch("builtins.input", side_effect=list(answers)), contextlib.redirect_stdout(out):
            code = cli.main(["--root", str(self.root), *argv])
        return code, out.getvalue()

    def test_review_approves_restores_and_skips(self) -> None:
        for key in ("a.tmp", "b.txt", "c.txt"):
            self.put(key)
        ids = [self.ask(key)["request_id"] for key in ("a.tmp", "b.txt", "c.txt")]
        code, out = self.run_cli("throne", "review", "--by", "alice",
                                 answers=["a", "yes", "r", "keep it", "s"])
        self.assertEqual(code, 0)
        self.assertIn("3 object(s) await your judgement", out)
        self.assertEqual([self.case(i)["status"] for i in ids], [Status.EXECUTED, Status.RESTORED, Status.QUARANTINED])
        self.assertEqual(self.case(ids[0])["decided_by"], "alice")
        self.assertIn("1 object(s) still await judgement", out)

    def test_approve_needs_an_explicit_yes(self) -> None:
        self.put("a.txt")
        request_id = self.ask("a.txt")["request_id"]
        self.run_cli("throne", "review", "--by", "alice", answers=["a", "no", "q"])
        self.assertEqual(self.case(request_id)["status"], Status.QUARANTINED)

    def test_freeze_from_review_skips_restored_cases(self) -> None:
        self.put("a.txt")
        self.put("b.txt")
        first = self.ask("a.txt")["request_id"]
        second = self.ask("b.txt")["request_id"]
        code, out = self.run_cli("throne", "review", "--by", "alice", answers=["f", "too eager", "y"])
        self.assertEqual(self.agent_status(), "frozen")
        self.assertEqual({self.case(first)["status"], self.case(second)["status"]}, {Status.RESTORED})
        self.assertIn("The quarantine is empty.", out)

    def test_end_of_input_quits_safely(self) -> None:
        self.put("a.txt")
        request_id = self.ask("a.txt")["request_id"]
        code, _ = self.run_cli("throne", "review", answers=[EOFError()])
        self.assertEqual(code, 0)
        self.assertEqual(self.case(request_id)["status"], Status.QUARANTINED)

    def test_status_reports_pending_and_not_running(self) -> None:
        self.put("a.txt")
        self.ask("a.txt")
        code, out = self.run_cli("status")
        self.assertEqual(code, 0)
        self.assertIn("not running", out)
        self.assertIn("1 awaiting judgement", out)
        self.assertIn("intact", out)


class DaemonTests(CastleTestCase):
    def test_pid_checks(self) -> None:
        self.assertTrue(daemon.pid_alive(os.getpid()))
        self.assertFalse(daemon.pid_alive(2**22 + 12345))
        self.assertIsNone(daemon.running(self.castle.config))

    def test_serve_writes_pid_and_obeys_the_stop_flag(self) -> None:
        self.castle.config.watchtower.patrol_interval_seconds = 0
        thread = threading.Thread(target=serve, args=(self.castle, "127.0.0.1", 0), daemon=True)
        thread.start()
        deadline = time.time() + 5
        while daemon.running(self.castle.config) is None and time.time() < deadline:
            time.sleep(0.05)
        pid, address = daemon.running(self.castle.config)
        self.assertEqual(pid, os.getpid())
        self.assertTrue(address.startswith("127.0.0.1:"))

        daemon.stop_path(self.castle.config).write_text("stop", "utf-8")
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertFalse(daemon.pid_path(self.castle.config).exists())
        self.assertFalse(daemon.stop_path(self.castle.config).exists())

    def test_stale_pid_file_is_ignored(self) -> None:
        daemon.pid_path(self.castle.config).write_text(f"{2**22 + 12345} 127.0.0.1:1\n", "utf-8")
        self.assertIsNone(daemon.running(self.castle.config))
        self.assertEqual(daemon.stop(self.castle.config), "not running")


if __name__ == "__main__":
    unittest.main()
