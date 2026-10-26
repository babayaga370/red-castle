"""The welcome screen."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from redcastle import banner, cli


class Utf8Out(io.StringIO):
    encoding = "utf-8"


class AsciiOut(io.StringIO):
    encoding = "ascii"


class BannerTests(unittest.TestCase):
    def test_castle_is_centered_under_the_title(self) -> None:
        text = banner.art(banner.Style(False), Utf8Out())
        lines = text.splitlines()
        self.assertEqual(lines[:6], banner.TITLE)
        widest = max(len(line) for line in lines if "|" in line)
        self.assertLessEqual(widest, len(banner.TITLE[0]))

    def test_falls_back_to_ascii(self) -> None:
        text = banner.art(banner.Style(False), AsciiOut())
        self.assertIn("R E D   C A S T L E", text)
        text.encode("ascii")  # must not raise

    def test_no_color_codes_when_not_a_terminal(self) -> None:
        self.assertNotIn("\033[", banner.welcome("redcastle", castle_here=False, stream=Utf8Out()))

    def test_welcome_adapts_to_an_existing_castle(self) -> None:
        fresh = banner.welcome("redcastle", castle_here=False, stream=Utf8Out())
        existing = banner.welcome("redcastle", castle_here=True, stream=Utf8Out())
        self.assertIn("redcastle init", fresh)
        self.assertNotIn("redcastle init", existing)
        self.assertIn("redcastle throne review", existing)

    def test_bare_command_and_init_show_the_banner(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["--root", tmp]), 0)
            self.assertIn("Getting started", out.getvalue())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["--root", tmp, "init"]), 0)
            self.assertIn("Your castle is founded", out.getvalue())
            self.assertTrue((Path(tmp) / "redcastle.toml").exists())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli.main(["--root", tmp])
            self.assertIn("A castle stands here", out.getvalue())


if __name__ == "__main__":
    unittest.main()
