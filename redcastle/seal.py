"""The royal seal: an HMAC the Throne Room puts on every death warrant.

The seal binds the decision to one case, one quarantine location and the exact
fingerprint of the object the human looked at. The Executioner will not act
on a warrant whose seal does not verify.
"""

from __future__ import annotations

import hashlib
import hmac


def royal_seal(key: bytes, request_id: str, location: str, checksum: str) -> str:
    message = "\n".join(("EXECUTE", request_id, location, checksum)).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def seal_is_valid(key: bytes, seal: str | None, request_id: str, location: str, checksum: str) -> bool:
    if not seal:
        return False
    return hmac.compare_digest(seal, royal_seal(key, request_id, location, checksum))
