"""Small helpers shared by the castle's roles."""

from __future__ import annotations

import fnmatch
import hashlib
import time
from datetime import datetime, timezone


def now() -> float:
    return time.time()


def iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def glob_match(key: str, pattern: str) -> bool:
    """Case-insensitive glob match where ``*`` also crosses folder boundaries.

    The key is tried both as-is and with a leading slash, so a pattern such as
    ``*/tmp/*`` matches ``tmp/x`` as well as ``a/tmp/x``.
    """
    k, p = key.casefold(), pattern.casefold()
    return fnmatch.fnmatchcase(k, p) or fnmatch.fnmatchcase("/" + k, p)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
