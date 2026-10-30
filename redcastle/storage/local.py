"""Local backend: the realm is a folder on disk, quarantine is a folder outside it."""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Iterable
from pathlib import Path

from .base import (
    Backend,
    InvalidKey,
    ObjectExists,
    ObjectInfo,
    ObjectNotFound,
    check_case_id,
    normalize_key,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


class LocalBackend(Backend):
    def __init__(
        self,
        realm: Path,
        quarantine_dir: Path,
        *,
        reserved: Iterable[Path] = (),
        can_purge: bool = False,
    ) -> None:
        super().__init__(can_purge=can_purge)
        self.realm = Path(realm).resolve()
        self.quarantine_dir = Path(quarantine_dir).resolve()
        self.realm.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        # The castle's own files are never part of the realm, even if the realm
        # is configured to be the folder the castle lives in.
        self.reserved = [Path(str(Path(p).resolve()).casefold()) for p in (*reserved, self.quarantine_dir)]

    def _is_reserved(self, path: Path) -> bool:
        # Not every disk cares about case, so neither does this check.
        folded = Path(str(path).casefold())
        return any(folded == r or folded.is_relative_to(r) for r in self.reserved)

    def _path(self, key: str) -> Path:
        key = normalize_key(key)
        if os.name == "nt" and ":" in key:
            raise InvalidKey("Object keys must not contain ':' on Windows.")
        candidate = self.realm / key
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError) as exc:  # a loop of links, for one
            raise InvalidKey(f"'{key}' cannot be resolved.") from exc
        if resolved == self.realm or not resolved.is_relative_to(self.realm):
            raise InvalidKey(f"'{key}' points outside the realm.")
        if self._is_reserved(resolved):
            raise InvalidKey(f"'{key}' belongs to the castle itself.")
        if candidate.is_symlink():
            raise InvalidKey(f"'{key}' is a symbolic link; links cannot be quarantined.")
        return candidate

    def _cell(self, location: str) -> Path:
        return self.quarantine_dir / check_case_id(location)

    def canonical_key(self, key: str) -> str:
        # The disk answers to more names than the real one - 'a.pem.', 'a.pem ' and
        # short names like 'SECRET~1.TXT' on Windows, and any folder link anywhere.
        return self._path(key).resolve().relative_to(self.realm).as_posix()

    def list_objects(self, prefix: str = "") -> list[ObjectInfo]:
        prefix = prefix.replace("\\", "/").lstrip("/")
        found = []
        for dirpath, dirnames, filenames in os.walk(self.realm):
            here = Path(dirpath)
            dirnames[:] = sorted(
                d for d in dirnames
                if not (here / d).is_symlink() and not self._is_reserved((here / d).resolve())
            )
            for name in filenames:
                path = here / name
                if path.is_symlink() or self._is_reserved(path.resolve()):
                    continue
                key = path.relative_to(self.realm).as_posix()
                if key.startswith(prefix):
                    try:
                        st = path.stat()
                    except OSError:  # gone since we looked: one file must not fail the whole listing
                        continue
                    found.append(ObjectInfo(key, st.st_size, st.st_mtime))
        return sorted(found, key=lambda o: o.key)

    def stat(self, key: str) -> ObjectInfo | None:
        path = self._path(key)
        if not path.is_file():
            return None
        st = path.stat()
        return ObjectInfo(normalize_key(key), st.st_size, st.st_mtime)

    def checksum(self, key: str) -> str | None:
        path = self._path(key)
        return _sha256(path) if path.is_file() else None

    def write(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def hide(self, key: str, case_id: str) -> str:
        source = self._path(key)
        if not source.is_file():
            raise ObjectNotFound(key)
        cell = self._cell(case_id)
        cell.mkdir(parents=True, exist_ok=False)
        try:
            shutil.move(source, cell / "object")
        except Exception:
            if source.is_file():  # a move that failed half-way may leave a stray copy behind
                shutil.rmtree(cell, ignore_errors=True)
            raise
        return case_id

    def unhide(self, location: str, key: str) -> None:
        cell = self._cell(location)
        source = cell / "object"
        if not source.is_file():
            raise ObjectNotFound(f"quarantine cell {location}")
        target = self._path(key)
        if target.exists():
            raise ObjectExists(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(source, target)
        try:
            cell.rmdir()
        except OSError:
            pass

    def find_hidden(self, key: str, case_id: str) -> str | None:
        return case_id if (self._cell(case_id) / "object").is_file() else None

    def quarantined_checksum(self, location: str) -> str | None:
        path = self._cell(location) / "object"
        return _sha256(path) if path.is_file() else None

    def _purge(self, location: str) -> None:
        cell = self._cell(location)
        path = cell / "object"
        if not path.is_file():
            raise ObjectNotFound(f"quarantine cell {location}")
        path.unlink()
        try:
            cell.rmdir()
        except OSError:
            pass
