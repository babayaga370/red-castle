"""Storage backends: where the realm's objects actually live."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..util import iso


class StorageError(Exception):
    """Base class for storage problems."""


class ObjectNotFound(StorageError):
    pass


class ObjectExists(StorageError):
    pass


class InvalidKey(StorageError):
    pass


@dataclass(frozen=True)
class ObjectInfo:
    key: str
    size: int
    modified: float  # unix timestamp

    def to_dict(self) -> dict:
        return {"key": self.key, "size": self.size, "modified": iso(self.modified)}


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")  # C0, DEL, C1 and broken Unicode
_CASE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


def normalize_key(key: object) -> str:
    """Return the canonical form of an object key, or raise InvalidKey."""
    if not isinstance(key, str):
        raise InvalidKey("The object key must be a string.")
    normalized = key.replace("\\", "/").lstrip("/")
    if not normalized or len(normalized) > 1024:
        raise InvalidKey("The object key must be 1-1024 characters long.")
    if _CONTROL.search(normalized):
        raise InvalidKey("The object key must not contain control characters or broken Unicode.")
    if any(part in ("", ".", "..") for part in normalized.split("/")):
        raise InvalidKey("The object key must not contain empty, '.' or '..' path segments.")
    return normalized


def check_case_id(case_id: str) -> str:
    if not _CASE_ID.fullmatch(case_id):
        raise InvalidKey(f"Invalid case id: {case_id!r}")
    return case_id


class Backend(ABC):
    """A place where objects live.

    The agents' view (``list_objects``/``stat``) never includes quarantined
    objects. ``purge`` is the only irreversible operation, and only a backend
    created for the Executioner (``can_purge=True``) will perform it.
    """

    def __init__(self, *, can_purge: bool = False) -> None:
        self.can_purge = can_purge

    def canonical_key(self, key: str) -> str:
        """The one name an object goes by here, whichever way ``key`` spells it.

        Every policy decision must be made on this name: a check on anything
        else can be walked around by spelling the same object differently.
        """
        return normalize_key(key)

    @abstractmethod
    def list_objects(self, prefix: str = "") -> list[ObjectInfo]:
        """Objects visible to the agents, sorted by key."""

    @abstractmethod
    def stat(self, key: str) -> ObjectInfo | None:
        """A visible object's metadata, or None if it does not exist."""

    @abstractmethod
    def checksum(self, key: str) -> str | None:
        """Fingerprint of a visible object, or None if it does not exist."""

    @abstractmethod
    def write(self, key: str, data: bytes) -> None:
        """Create or overwrite a visible object (used to plant canaries)."""

    @abstractmethod
    def hide(self, key: str, case_id: str) -> str:
        """Move an object out of the agents' sight. Returns an opaque location."""

    @abstractmethod
    def unhide(self, location: str, key: str) -> None:
        """Bring a quarantined object back as ``key``; ObjectExists if taken."""

    @abstractmethod
    def find_hidden(self, key: str, case_id: str) -> str | None:
        """Where a request that was cut short left its object, or None if it never got there."""

    @abstractmethod
    def quarantined_checksum(self, location: str) -> str | None:
        """Fingerprint of a quarantined object, or None if it is gone."""

    def purge(self, location: str) -> None:
        """Permanently destroy a quarantined object."""
        if not self.can_purge:
            raise PermissionError("Only the Executioner may permanently delete objects.")
        self._purge(location)

    @abstractmethod
    def _purge(self, location: str) -> None: ...
