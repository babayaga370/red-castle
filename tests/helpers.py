from __future__ import annotations

import logging
import os
import tempfile
import time
import unittest
from pathlib import Path

# Never pop up real desktop notifications while testing.
os.environ["REDCASTLE_NOTIFY"] = "off"

from redcastle.castle import found_castle  # noqa: E402

WEEK = 7 * 86400


class CastleTestCase(unittest.TestCase):
    """A fresh castle with a local realm and one registered agent per test.

    Notifications are captured in ``self.notifications`` and sent at once.
    """

    def setUp(self) -> None:
        logging.disable(logging.CRITICAL)
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self._tmp.name)
        self.castle = found_castle(self.root)
        self.notifications: list[tuple[str, str, str, bool]] = []
        self.castle.notifier.sender = lambda *n: self.notifications.append(n)
        self.castle.config.notify.batch_seconds = 0
        self.realm = self.castle.config.realm_path
        self.token = self.castle.registry.add_agent("tester")
        self.gw = self.castle.gateway

    def tearDown(self) -> None:
        self.castle.close()
        self._tmp.cleanup()
        logging.disable(logging.NOTSET)

    def put(self, key: str, data: bytes = b"data", age: float = WEEK) -> Path:
        path = self.realm / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        t = time.time() - age
        os.utime(path, (t, t))
        return path

    def ask(self, key: str, reason: str = "No longer needed by the project", score: object = 30,
            token: str | None = None) -> dict:
        return self.gw.request_deletion(token or self.token, key, reason, score)

    def case(self, request_id: str) -> dict:
        return self.castle.registry.get_request(request_id)

    def agent_status(self, name: str = "tester") -> str:
        return self.castle.registry.get_agent(name)["status"]
