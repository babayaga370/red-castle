"""Desktop notifications: when the castle speaks up, and when it stays quiet."""

from __future__ import annotations

import time
import unittest
from unittest import mock

from redcastle import notify
from redcastle.config import NotifyConfig
from redcastle.notify import Notifier, compose

from .helpers import CastleTestCase


def case(agent: str = "bot", key: str = "a.txt", flag: str | None = None, age: float = 0) -> dict:
    return {
        "agent": agent, "object_key": key, "judge_score": 40, "judge_level": "medium",
        "agent_score": 10, "flag": flag, "created_at": time.time() - age,
    }


class NotifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sent: list[tuple] = []
        self.config = NotifyConfig(batch_seconds=60)
        self.notifier = Notifier(self.config, sender=lambda *n: self.sent.append(n))

    def test_bursts_are_gathered_into_one_notification(self) -> None:
        for i in range(5):
            self.notifier.awaiting(case(agent="bot" if i % 2 else "claude", key=f"f{i}.txt"))
        self.assertEqual(self.sent, [])  # still gathering
        self.notifier.flush()
        self.assertEqual(len(self.sent), 1)
        title, line1, _, urgent = self.sent[0]
        self.assertIn("5 objects", title)
        self.assertIn("bot, claude", line1)
        self.assertFalse(urgent)

    def test_batch_is_sent_when_the_timer_fires(self) -> None:
        self.config.batch_seconds = 0.05
        self.notifier.awaiting(case())
        deadline = time.time() + 5
        while not self.sent and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual(len(self.sent), 1)

    def test_severity_threshold(self) -> None:
        self.config.batch_seconds = 0
        self.config.min_severity = "critical"
        self.notifier.alert("warning", "meh")
        self.assertEqual(self.sent, [])
        self.notifier.alert("critical", "fire")
        self.assertEqual(self.sent[0][1], "fire")
        self.assertTrue(self.sent[0][3])

    def test_agent_text_is_defused_before_it_reaches_the_screen(self) -> None:
        self.config.batch_seconds = 0
        self.notifier.awaiting(case(key="report‮txt.exe"))
        self.assertNotIn("‮", self.sent[0][1])
        self.assertIn("\\u202e", self.sent[0][1])

    def test_disabled(self) -> None:
        self.config.enabled = False
        self.notifier.alert("critical", "fire")
        self.notifier.awaiting(case())
        self.notifier.flush()
        self.assertEqual(self.sent, [])

    def test_reminders_respect_the_interval(self) -> None:
        self.config.remind_interval_minutes = 60
        fresh, old = case(age=60), case(age=2 * 3600)
        self.assertFalse(self.notifier.remind([fresh]))
        self.assertTrue(self.notifier.remind([fresh, old]))
        self.assertFalse(self.notifier.remind([fresh, old]))  # not again within the hour
        self.assertTrue(self.notifier.remind([old], now=time.time() + 3601))
        self.assertIn("1 object has waited", self.sent[0][1])

    def test_a_failing_notifier_never_breaks_the_castle(self) -> None:
        def broken(*_: object) -> None:
            raise RuntimeError("no desktop here")

        notifier = Notifier(NotifyConfig(batch_seconds=0), sender=broken)
        notifier.alert("critical", "fire")  # must not raise

    def test_compose_mixed_batch_is_urgent(self) -> None:
        title, line1, line2, urgent = compose([("critical", "Trap sprung")], [case(), case()])
        self.assertTrue(urgent)
        self.assertEqual(line1, "Trap sprung")
        self.assertIn("2 objects await", line2)

    def test_single_case_mentions_underestimate(self) -> None:
        _, line1, line2, _ = compose([], [case(key="config/prod.env", flag="underestimated")])
        self.assertIn("config/prod.env", line1)
        self.assertIn("UNDERESTIMATED", line2)


class PlantedProgramTests(unittest.TestCase):
    def test_programs_are_never_looked_up_by_bare_name(self) -> None:
        # Windows would otherwise run a powershell.exe planted in the current folder.
        with mock.patch("redcastle.notify.subprocess.run") as run:
            run.return_value.returncode = 0
            notify._windows_toast("title", "one", "two", False)
            notify._macos_notification("title", "one", "two", False)
        programs = [call.args[0][0] for call in run.call_args_list]
        self.assertIn("System32", programs[0])
        self.assertEqual(programs[1], "/usr/bin/osascript")


class CastleNotificationTests(CastleTestCase):
    def test_quarantine_notifies_the_human(self) -> None:
        self.put("config/prod.env")
        self.ask("config/prod.env", score=0)
        self.assertEqual(len(self.notifications), 1)  # the underestimate warning rides along, no extra toast
        title, line1, line2, urgent = self.notifications[0]
        self.assertIn("awaiting your judgement", title)
        self.assertIn("tester wants to delete config/prod.env", line1)
        self.assertIn("UNDERESTIMATED", line2)

    def test_rejections_stay_quiet(self) -> None:
        self.ask("missing.txt")
        self.ask("../escape.txt")
        self.assertEqual(self.notifications, [])

    def test_sprung_trap_is_urgent(self) -> None:
        self.castle.traps.plant("bait.txt")
        self.ask("bait.txt")
        self.assertTrue(self.notifications)
        self.assertTrue(all(n[3] for n in self.notifications))
        self.assertTrue(any("canary" in n[1] for n in self.notifications))

    def test_patrol_problem_notifies_once(self) -> None:
        self.castle.traps.plant("bait.txt")
        (self.realm / "bait.txt").unlink()
        self.castle.patrol()
        self.castle.patrol()
        self.assertEqual(len(self.notifications), 1)
        self.assertTrue(self.notifications[0][3])

    def test_close_flushes_a_waiting_batch(self) -> None:
        self.castle.config.notify.batch_seconds = 3600
        self.put("a.txt")
        self.ask("a.txt")
        self.assertEqual(self.notifications, [])
        self.castle.notifier.flush()  # what Castle.close() does
        self.assertEqual(len(self.notifications), 1)


if __name__ == "__main__":
    unittest.main()
