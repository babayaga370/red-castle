"""The castle: wires every role together."""

from __future__ import annotations

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
    render_config,
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
        self.lock = threading.RLock()  # serializes requests from the HTTP server's threads
        config.state_dir.mkdir(parents=True, exist_ok=True)
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
        return self.watchtower.patrol(self.traps, self.backend)

    def close(self) -> None:
        self.notifier.flush()  # do not swallow a batch that is still waiting
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
        config_path.write_text(render_config(fresh), "utf-8")
    config = load_config(root)
    secrets = create_secrets(config.secrets_path)
    (config.state_dir / ".gitignore").write_text("*\n", "utf-8")
    castle = Castle(config, secrets)
    castle.chronicle.record("castle", "castle.founded", root=str(root), backend=config.storage.backend)
    return castle
