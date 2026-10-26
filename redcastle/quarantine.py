"""The Quarantine: the object is hidden from the agents but still exists."""

from __future__ import annotations

from .chronicle import Chronicle
from .storage import Backend, StorageError


class Quarantine:
    def __init__(self, backend: Backend, chronicle: Chronicle) -> None:
        self.backend = backend
        self.chronicle = chronicle

    def hide(self, request_id: str, key: str) -> tuple[str, str]:
        """Hide the object. Returns its quarantine location and fingerprint."""
        location = self.backend.hide(key, request_id)
        checksum = self.backend.quarantined_checksum(location)
        if checksum is None:
            raise StorageError(f"'{key}' vanished right after it was quarantined.")
        self.chronicle.record(
            "quarantine", "quarantine.hidden",
            request_id=request_id, key=key, location=location, checksum=checksum,
        )
        return location, checksum

    def release(self, request_id: str, location: str, key: str) -> None:
        """Put the object back where the agents can see it."""
        self.backend.unhide(location, key)
        self.chronicle.record("quarantine", "quarantine.released", request_id=request_id, key=key)

    def intact(self, location: str, checksum: str) -> bool:
        return self.backend.quarantined_checksum(location) == checksum
