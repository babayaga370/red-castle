"""Storage backends for the realm."""

from __future__ import annotations

from ..config import CONFIG_FILE, Config, ConfigError
from .base import (
    Backend,
    InvalidKey,
    ObjectExists,
    ObjectInfo,
    ObjectNotFound,
    StorageError,
    normalize_key,
)
from .local import LocalBackend

__all__ = [
    "Backend", "InvalidKey", "LocalBackend", "ObjectExists", "ObjectInfo",
    "ObjectNotFound", "StorageError", "make_backend", "normalize_key",
]


def make_backend(config: Config, *, executioner: bool = False) -> Backend:
    """Create the backend for the castle, or (``executioner=True``) the one handle that may purge."""
    storage = config.storage
    if storage.backend == "local":
        return LocalBackend(
            config.realm_path,
            config.quarantine_dir,
            reserved=(config.state_dir, config.root / CONFIG_FILE),
            can_purge=executioner,
        )
    if storage.backend == "s3":
        from .s3 import S3Backend

        return S3Backend.from_config(storage, executioner=executioner)
    raise ConfigError(f"Unknown storage backend '{storage.backend}' (use 'local' or 's3').")
