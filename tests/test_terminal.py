"""Working from the terminal: the review loop, status, and the background server's lifecycle."""

from __future__ import annotations

import contextlib
import io
import logging
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

from redcastle import cli, daemon
from redcastle.api import serve
from redcastle.gateway import GatewayError
from redcastle.registry import Status
from redcastle.throne import ThroneError

from .helpers import CastleTestCase


class ReviewTests(CastleTestCase):
    def run_cli(self, *argv: str, answers: list = (), terminal: bool = True) -> tuple[int, str]:
        out = io.StringIO()
        self.err = io.StringIO()
        with (
            mock.patch("builtins.input", side_effect=list(answers)),
            mock.patch("redcastle.cli._at_a_terminal", return_value=terminal),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(self.err),
        ):
            code = cli.main(["--root", str(self.root), *argv])
        return code, out.getvalue()

    def test_review_approves_restores_and_skips(self) -> None:
        for key in ("a.tmp", "b.txt", "c.txt"):
            self.put(key)
        ids = [self.ask(key)["request_id"] for key in ("a.tmp", "b.txt", "c.txt")]
        code, out = self.run_cli("throne", "review", "--by", "alice",
                                 answers=["a", ids[0][-4:], "r", "keep it", "s"])
        self.assertEqual(code, 0)
        self.assertIn("3 object(s) await your judgement", out)
        self.assertEqual([self.case(i)["status"] for i in ids], [Status.EXECUTED, Status.RESTORED, Status.QUARANTINED])
        self.assertEqual(self.case(ids[0])["decided_by"], "alice")
        self.assertIn("1 object(s) still await judgement", out)

    def test_approve_needs_the_code_of_this_very_case(self) -> None:
        self.put("a.txt")
        request_id = self.ask("a.txt")["request_id"]
        self.run_cli("throne", "review", "--by", "alice", answers=["a", "yes", "q"])
        self.assertEqual(self.case(request_id)["status"], Status.QUARANTINED)
        self.assertEqual(self.run_cli("throne", "approve", request_id, answers=["yes"])[0], 1)
        self.assertEqual(self.case(request_id)["status"], Status.QUARANTINED)
        self.assertEqual(self.run_cli("throne", "approve", request_id, "--by", "alice", answers=[request_id[-4:]])[0], 0)
        self.assertEqual(self.case(request_id)["status"], Status.EXECUTED)

    def test_approving_cannot_skip_the_question(self) -> None:
        self.put("a.txt")
        request_id = self.ask("a.txt")["request_id"]
        with self.assertRaises(SystemExit):
            self.run_cli("throne", "approve", request_id, "--yes")
        self.assertEqual(self.case(request_id)["status"], Status.QUARANTINED)

    def test_decisions_need_a_human_at_a_terminal(self) -> None:
        self.put("a.txt")
        request_id = self.ask("a.txt")["request_id"]
        self.castle.registry.freeze_agent("tester", by="watchtower", reason="sprang a trap")
        self.castle.traps.plant("bait.txt")
        for argv in (
            ("throne", "approve", request_id), ("throne", "review"), ("throne", "unfreeze", "tester"),
            ("agent", "add", "sneaky"), ("agent", "rotate", "tester"), ("traps", "remove", "bait.txt"),
        ):
            self.assertEqual(self.run_cli(*argv, terminal=False)[0], 2, argv)
            self.assertIn("human", self.err.getvalue())
        self.assertEqual(self.case(request_id)["status"], Status.QUARANTINED)
        self.assertEqual(self.agent_status(), "frozen")
        self.assertIsNone(self.castle.registry.get_agent("sneaky"))
        self.assertEqual(len(self.castle.traps.list()), 1)

    def test_a_process_without_a_terminal_is_told_so_for_real(self) -> None:
        # On Windows the null device claims to be a terminal, so this must go through a real process.
        for stdin in (subprocess.DEVNULL, subprocess.PIPE):
            done = subprocess.run(
                [sys.executable, "-m", "redcastle", "--root", str(self.root), "agent", "add", "sneaky"],
                stdin=stdin, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIsNone(self.castle.registry.get_agent("sneaky"))

    def test_log_lines_cannot_steer_the_terminal(self) -> None:
        record = logging.LogRecord("x", logging.INFO, __file__, 1, "GET /\x1b[2J\nforged line", None, None)
        self.assertEqual(cli.SafeFormatter("%(message)s").format(record), "GET /\\x1b[2J\\nforged line")

    def test_error_messages_cannot_steer_the_terminal_either(self) -> None:
        self.assertEqual(self.run_cli("throne", "show", "rc-\x1b[2J")[0], 2)
        self.assertNotIn("\x1b", self.err.getvalue())

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

    def test_status_shows_approved_cases_left_undone(self) -> None:
        self.put("a.txt")
        request_id = self.ask("a.txt")["request_id"]
        location = self.case(request_id)["quarantine_location"]
        (self.castle.config.quarantine_dir / location / "object").write_bytes(b"swapped")
        with self.assertRaises(ThroneError):
            self.castle.throne.approve(request_id, by="alice")
        self.assertIn("1 not carried out", self.run_cli("status")[1])

    def test_agent_text_cannot_steer_the_terminal(self) -> None:
        self.put("config/prod.env")
        forged = "Unused\x1b[2K\x1b[1A\r  risk:       agent 90, Judge 5 (low)\n  object:     harmless.tmp‮"
        self.ask("config/prod.env", reason=forged, score=90)
        _, out = self.run_cli("throne", "review", "--by", "alice", answers=["s"])
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\n  object:     harmless.tmp", out)
        self.assertNotIn("‮", out)
        self.assertIn("\\x1b[2K", out)  # spelled out, so the human sees that someone tried

    def test_tables_cannot_be_steered_either(self) -> None:
        self.assertNotIn("\x1b", cli._table([["\x1b[31mred"]], ["CELL"]))

    def test_root_is_accepted_after_the_command(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["throne", "list", "--root", str(self.root)]), 0)

    def test_mistakes_end_in_a_message_not_a_traceback(self) -> None:
        code, _ = self.run_cli("traps", "plant", "../outside")
        self.assertEqual(code, 2)
        self.assertIn("error:", self.err.getvalue())

    def test_a_leaked_token_can_be_replaced(self) -> None:
        code, out = self.run_cli("agent", "rotate", "tester")
        self.assertEqual(code, 0)
        with self.assertRaises(GatewayError):
            self.gw.authenticate(self.token)
        self.assertEqual(self.gw.authenticate(out.split()[-1])["name"], "tester")
        self.assertEqual(self.run_cli("agent", "rotate", "nobody")[0], 2)

    def test_a_published_head_can_be_checked_later(self) -> None:
        self.put("a.txt")
        self.ask("a.txt")
        head = self.run_cli("chronicle", "verify")[1].split("Head: ")[1].strip()
        self.assertEqual(self.run_cli("chronicle", "verify", "--head", head)[0], 0)
        self.assertEqual(self.run_cli("chronicle", "verify", "--head", "not-a-head")[0], 1)
        conn = self.castle.db.conn
        conn.execute("DROP TRIGGER chronicle_no_delete")
        conn.execute("DELETE FROM chronicle WHERE seq = ?", (int(head.split(":")[0]),))
        code, out = self.run_cli("chronicle", "verify", "--head", head)
        self.assertEqual(code, 1)
        self.assertIn("TRUNCATED", out)  # the chain alone still verifies: only the head can tell


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

    def test_the_background_castle_loads_nothing_from_its_folder(self) -> None:
        with mock.patch("redcastle.daemon.subprocess.Popen") as popen:
            daemon.launch_background(self.castle.config, [])
        self.assertIn("-P", popen.call_args.args[0])
        self.assertEqual(popen.call_args.kwargs["cwd"], str(self.castle.config.state_dir))

    def child(self, code: str) -> subprocess.Popen:
        process = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        return process

    def hung_castle(self) -> tuple[subprocess.Popen, int]:
        """A process that holds the gate, wrote its pid and then stopped listening to anyone.

        Also returns that pid: in a venv on Windows, Popen only sees a launcher in front of it.
        """
        process = self.child(
            "import os, time\n"
            "from redcastle import daemon\n"
            "from redcastle.config import load_config\n"
            f"config = load_config({str(self.root)!r})\n"
            "with daemon.holding_gate(config):\n"
            "    daemon.write_pid(config, '127.0.0.1', 1)\n"
            "    print(os.getpid(), flush=True)\n"
            "    time.sleep(60)\n"
        )
        return process, int(process.stdout.readline())

    def test_stop_leaves_a_stranger_with_a_reused_pid_alone(self) -> None:
        stranger = self.child("import time; time.sleep(60)")
        daemon.pid_path(self.castle.config).write_text(f"{stranger.pid} 127.0.0.1:1\n", "utf-8")
        self.assertIsNone(daemon.running(self.castle.config))
        self.assertEqual(daemon.stop(self.castle.config, timeout=0.2), "not running")
        self.assertIsNone(stranger.poll())

    def test_stop_still_forces_a_castle_that_hangs(self) -> None:
        hung, pid = self.hung_castle()
        self.assertEqual(daemon.running(self.castle.config)[0], pid)
        self.assertEqual(daemon.stop(self.castle.config, timeout=0.2), "killed")
        hung.wait(timeout=10)
        self.assertFalse(daemon.pid_alive(pid))

    def test_the_gate_opens_when_a_castle_dies(self) -> None:
        hung, _ = self.hung_castle()
        self.assertTrue(daemon.gate_held(self.castle.config))
        hung.kill()
        hung.wait()
        deadline = time.time() + 5
        while daemon.gate_held(self.castle.config) and time.time() < deadline:
            time.sleep(0.05)
        self.assertIsNone(daemon.running(self.castle.config))

    def test_only_one_castle_runs_from_a_folder(self) -> None:
        with daemon.holding_gate(self.castle.config):
            self.assertTrue(daemon.gate_held(self.castle.config))
            with self.assertRaises(OSError):
                serve(self.castle, "127.0.0.1", 0)
        self.assertFalse(daemon.gate_held(self.castle.config))

    def test_a_blind_watchtower_is_reported_once(self) -> None:
        self.castle.config.watchtower.patrol_interval_seconds = 0.02
        with mock.patch.object(self.castle, "patrol", side_effect=RuntimeError("no patrol today")):
            thread = threading.Thread(target=serve, args=(self.castle, "127.0.0.1", 0), daemon=True)
            thread.start()
            deadline = time.time() + 5
            while not self.castle.watchtower.alerts() and time.time() < deadline:
                time.sleep(0.02)
            time.sleep(0.1)  # time for more failed patrols
            daemon.stop_path(self.castle.config).write_text("stop", "utf-8")
            thread.join(timeout=10)
        self.assertEqual([a["kind"] for a in self.castle.watchtower.alerts()], ["patrol_failed"])
        self.assertTrue(self.notifications[0][3])


if __name__ == "__main__":
    unittest.main()
