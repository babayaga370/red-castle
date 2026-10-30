"""Small helpers shared by the castle's roles."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path


def now() -> float:
    return time.time()


def iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def fold(text: str) -> str:
    """The form in which names are compared: ignores case and look-alike Unicode spellings."""
    return unicodedata.normalize("NFKC", text).casefold()


def glob_match(key: str, pattern: str) -> bool:
    """Case-insensitive glob match where ``*`` also crosses folder boundaries.

    The key is tried both as-is and with a leading slash, so a pattern such as
    ``*/tmp/*`` matches ``tmp/x`` as well as ``a/tmp/x``.
    """
    k, p = fold(key), fold(pattern)
    return fnmatch.fnmatchcase(k, p) or fnmatch.fnmatchcase("/" + k, p)


def printable(text: str) -> str:
    """``text`` made safe to show a human: escape sequences, line breaks and bidi overrides are spelled out.

    Agents write object keys and reasons, and the human decides by reading
    them, so nothing an agent writes may steer the terminal or forge a line.
    """
    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in text)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def windows_tool(name: str) -> str:
    """The full path of a program that ships with Windows.

    Windows looks for a bare program name in the current folder first, and
    that may be a folder an agent can write to.
    """
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / name)
