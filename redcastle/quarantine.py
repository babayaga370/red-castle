"""The Quarantine: the object is hidden from the agents but still exists."""

from __future__ import annotations

from .chronicle import Chronicle
from .storage import Backend, InvalidKey, StorageError


class StrandedObject(StorageError):
    """The object sits in a cell, and could not be put back where it came from."""


class Quarantine:
    def __init__(self, backend: Backend, chronicle: Chronicle) -> None:
        self.backend = backend
        self.chronicle = chronicle

    def hide(self, request_id: str, key: str) -> tuple[str, str]:
        """Hide the object. Returns its quarantine location and fingerprint."""
        location = self.backend.hide(key, request_id)
        try:
            checksum = self.backend.quarantined_checksum(location)
            if checksum is None:
                raise StorageError(f"'{key}' vanished right after it was quarantined.")
            self.chronicle.record(
                "quarantine", "quarantine.hidden",
                request_id=request_id, key=key, location=location, checksum=checksum,
            )
        except Exception as exc:
            # No case will ever point at this cell, so nobody could reach the object.
            try:
                self.backend.unhide(location, key)
            except Exception as stuck:  # noqa: BLE001 - locked by another program, say
                raise StrandedObject(f"{exc}; putting it back failed too: {stuck}") from exc
            raise
        return location, checksum

    def find(self, request_id: str, key: str) -> tuple[str, str] | None:
        """Where a request that was cut short left its object, and its fingerprint."""
        try:
            location = self.backend.find_hidden(key, request_id)
        except InvalidKey:  # the request never got past the Moat
            return None
        checksum = self.backend.quarantined_checksum(location) if location else None
        return (location, checksum) if location and checksum else None

    def release(self, request_id: str, location: str, key: str) -> None:
        """Put the object back where the agents can see it."""
        self.backend.unhide(location, key)
        self.chronicle.record("quarantine", "quarantine.released", request_id=request_id, key=key)

    def intact(self, location: str, checksum: str) -> bool:
        return self.backend.quarantined_checksum(location) == checksum
