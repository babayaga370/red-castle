"""The castle: wires every role together."""

from __future__ import annotations

import os
import threading
from pathlib import Path

from .chronicle import Chronicle
from .config import (
    CONFIG_FILE,
    Config,
    Secrets,
    create_secrets,
    load_config,
    load_secrets,
    make_private,
    render_config,
    write_private,
)
from .db import Database
from .executioner import Executioner
from .gateway import Gateway
from .judge import Judge
from .moat import Moat
from .notify import Notifier
from .quarantine import Quarantine
from .registry import Registry
from .storage import Backend, make_backend
from .throne import ThroneRoom
from .traps import Traps
from .watchtower import Watchtower


def _lock_up(config: Config) -> None:
    """Keep the keys, the database and the config from other OS users; Windows needs telling only once."""
    marker = config.state_dir / ".private"
    if os.name == "nt" and marker.exists():
        return
    config.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths = [p for p in (config.state_dir, config.root / CONFIG_FILE) if p.exists()]
    if all([make_private(path) for path in paths]):
        marker.touch()


class Castle:
    def __init__(
        self,
        config: Config,
        secrets: Secrets,
        *,
        backend: Backend | None = None,
        executioner_backend: Backend | None = None,
        notifier: Notifier | None = None,
    ) -> None:
        self.config = config
        self.lock = threading.RLock()  # deletion requests are decided and carried out one at a time
        _lock_up(config)
        self.db = Database(config.db_path)
        self.registry = Registry(self.db)
        self.chronicle = Chronicle(self.db, secrets.chronicle_key)
        self.backend = backend or make_backend(config)
        self.notifier = notifier or Notifier(config.notify)
        self.watchtower = Watchtower(self.db, self.registry, self.chronicle, config.watchtower, self.notifier)
        self.traps = Traps(self.db, self.backend, self.chronicle)
        self.moat = Moat(config.moat, self.registry)
        self.judge = Judge(config.judge, self.registry)
        self.quarantine = Quarantine(self.backend, self.chronicle)
        # The Executioner gets its own storage handle - the only one allowed to purge.
        self.executioner = Executioner(
            self.registry,
            executioner_backend or make_backend(config, executioner=True),
            self.chronicle,
            self.watchtower,
            secrets.seal_key,
        )
        self.throne = ThroneRoom(
            self.registry, self.quarantine, self.executioner, self.chronicle, secrets.seal_key
        )
        self.gateway = Gateway(self)

    @classmethod
    def open(cls, root: Path | str) -> Castle:
        config = load_config(root)
        return cls(config, load_secrets(config.secrets_path))

    def patrol(self) -> dict:
        with self.lock:
            self.gateway.settle_interrupted()
        # Outside the lock: hashing the quarantine must not hold up the Gateway.
        return self.watchtower.patrol(self.traps, self.backend)

    def close(self) -> None:
        self.notifier.flush()  # do not swallow a batch that is still waiting
        self.watchtower.close()
        self.db.close()

    def __enter__(self) -> Castle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def found_castle(root: Path | str, *, realm: str = "realm") -> Castle:
    """Create a new castle in ``root``."""
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    config_path = root / CONFIG_FILE
    if not config_path.exists():
        fresh = Config(root=root)
        fresh.storage.realm = realm
        write_private(config_path, render_config(fresh))
    config = load_config(root)
    _lock_up(config)  # before the keys exist, not after
    secrets = create_secrets(config.secrets_path)
    (config.state_dir / ".gitignore").write_text("*\n", "utf-8")
    castle = Castle(config, secrets)
    castle.chronicle.record("castle", "castle.founded", root=str(root), backend=config.storage.backend)
    return castle
