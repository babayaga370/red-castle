"""redcastle.toml and the castle's keys."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from redcastle.castle import Castle, found_castle
from redcastle.config import CONFIG_FILE, Config, ConfigError, create_secrets, load_config, load_secrets, render_config


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def write(self, text: str) -> None:
        (self.root / CONFIG_FILE).write_text(text, "utf-8")

    def test_a_rendered_config_loads_back_unchanged(self) -> None:
        fresh = Config(root=self.root.resolve())
        self.write(render_config(fresh))
        self.assertEqual(load_config(self.root), fresh)

    def test_mistakes_are_refused_when_the_castle_opens(self) -> None:
        mistakes = {
            "[nonsense]\nx = 1": "nonsense",
            "[moat]\nnonsense = 1": "nonsense",
            '[moat]\nmax_requests_per_minute = "ten"': "max_requests_per_minute",
            "[moat]\nmax_requests_per_minute = true": "max_requests_per_minute",
            "[moat]\nprotected_patterns = [1]": "protected_patterns",
            "[server]\nport = 99999": "port",
            '[notify]\nmin_severity = "critcal"': "min_severity",
            '[judge.sensitive_patterns]\n"*.env" = "high"': "*.env",
            '[judge.low_value_patterns]\n"*.tmp" = true': "*.tmp",
            '[watchtower]\nwebhook_url = "file:///etc/passwd"': "webhook_url",
        }
        for text, named in mistakes.items():
            self.write(text)
            with self.assertRaisesRegex(ConfigError, named.replace("*", r"\*"), msg=text):
                load_config(self.root)


class SecretsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.path = self.root / ".redcastle" / "secrets.json"

    def test_keys_are_never_overwritten(self) -> None:
        keys = create_secrets(self.path)
        with self.assertRaises(ConfigError):
            create_secrets(self.path)
        self.assertEqual(load_secrets(self.path), keys)

    def test_damaged_keys_are_a_clean_error(self) -> None:
        self.path.parent.mkdir()
        for text in ("not json", "[]", "{}", '{"chronicle_key": "zz", "seal_key": "00"}'):
            self.path.write_text(text, "utf-8")
            with self.assertRaises(ConfigError, msg=text):
                load_secrets(self.path)

    @unittest.skipIf(os.name == "nt", "Windows protects files with ACLs, not mode bits")
    def test_keys_are_for_the_castle_alone(self) -> None:
        with found_castle(self.root) as castle:
            self.assertEqual(stat.S_IMODE(castle.config.state_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(castle.config.secrets_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((self.root / CONFIG_FILE).stat().st_mode), 0o600)  # webhook URLs are secrets

    @unittest.skipIf(os.name == "nt", "Windows protects files with ACLs, not mode bits")
    def test_a_castle_left_open_is_closed_up(self) -> None:
        found_castle(self.root).close()
        state_dir = self.path.parent
        state_dir.chmod(0o755)
        (self.root / CONFIG_FILE).chmod(0o644)
        Castle.open(self.root).close()
        self.assertEqual(stat.S_IMODE(state_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / CONFIG_FILE).stat().st_mode), 0o600)

    def sddl(self, path: Path) -> str:
        saved = self.root / "acl.txt"
        subprocess.run(["icacls", str(path), "/save", str(saved)], check=True, capture_output=True)
        return saved.read_bytes().decode("utf-16-le")

    def assert_closed(self, path: Path) -> None:
        sddl = self.sddl(path)
        self.assertIn("D:P", sddl, path)  # nothing inherited from the folder it happens to live in
        for everyday_users in (";;;BU)", ";;;AU)", ";;;WD)"):
            self.assertNotIn(everyday_users, sddl, path)

    @unittest.skipUnless(os.name == "nt", "ACLs are a Windows matter")
    def test_windows_keeps_other_users_out(self) -> None:
        with found_castle(self.root) as castle:
            self.assert_closed(castle.config.state_dir)
            self.assert_closed(self.root / CONFIG_FILE)

    @unittest.skipUnless(os.name == "nt", "ACLs are a Windows matter")
    def test_an_older_windows_castle_is_closed_up_too(self) -> None:
        found_castle(self.root).close()
        state_dir = self.path.parent
        (state_dir / ".private").unlink()
        subprocess.run(["icacls", str(state_dir), "/inheritance:e"], check=True, capture_output=True)
        subprocess.run(["icacls", str(self.root / CONFIG_FILE), "/inheritance:e"], check=True, capture_output=True)
        self.assertNotIn("D:P", self.sddl(self.root / CONFIG_FILE))
        Castle.open(self.root).close()
        self.assert_closed(state_dir)
        self.assert_closed(self.root / CONFIG_FILE)


if __name__ == "__main__":
    unittest.main()
