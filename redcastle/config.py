"""Configuration (redcastle.toml) and the castle's keys (.redcastle/secrets.json)."""

from __future__ import annotations

import json
import secrets as _secrets
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

CONFIG_FILE = "redcastle.toml"
STATE_DIR = ".redcastle"


class ConfigError(Exception):
    """Raised for an invalid or missing configuration."""


def _sensitive_patterns() -> dict[str, int]:
    return {
        "*.env": 35,
        "*.env.*": 35,
        "*secret*": 35,
        "*password*": 35,
        "*credential*": 35,
        "*.tfstate*": 35,
        "*backup*": 25,
        "*.bak": 25,
        "*.db": 25,
        "*.sqlite*": 25,
        "*.sql": 20,
        "*prod*": 20,
        "*.py": 10,
        "*.js": 10,
        "*.ts": 10,
        "*.docx": 10,
        "*.xlsx": 10,
        "*.pdf": 10,
    }


def _low_value_patterns() -> dict[str, int]:
    return {
        "*.tmp": -15,
        "*.temp": -15,
        "*.log": -10,
        "*.cache": -15,
        "*~": -15,
        "*.pyc": -15,
        "*/__pycache__/*": -15,
        "*/node_modules/*": -15,
        "*/tmp/*": -10,
    }


@dataclass
class StorageConfig:
    backend: str = "local"
    realm: str = "realm"
    bucket: str = ""
    prefix: str = ""
    quarantine_prefix: str = ".redcastle-quarantine/"
    region: str = ""
    profile: str = ""
    executioner_profile: str = ""


@dataclass
class MoatConfig:
    max_requests_per_minute: int = 10
    max_requests_per_day: int = 200
    min_reason_length: int = 10
    protected_patterns: list[str] = field(
        default_factory=lambda: ["*.pem", "*.key", "*/.git/*", "*/.ssh/*"]
    )


@dataclass
class JudgeConfig:
    discrepancy_threshold: int = 25
    burst_window_minutes: int = 10
    burst_threshold: int = 5
    sensitive_patterns: dict[str, int] = field(default_factory=_sensitive_patterns)
    low_value_patterns: dict[str, int] = field(default_factory=_low_value_patterns)


@dataclass
class WatchtowerConfig:
    underestimate_limit: int = 3
    underestimate_window_minutes: int = 60
    rejection_limit: int = 5
    rejection_window_minutes: int = 10
    patrol_interval_seconds: int = 60
    webhook_url: str = ""


@dataclass
class NotifyConfig:
    enabled: bool = True
    on_quarantine: bool = True
    min_severity: str = "warning"
    batch_seconds: int = 3
    remind_interval_minutes: int = 60


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8750


SECTIONS = {
    "storage": StorageConfig,
    "moat": MoatConfig,
    "judge": JudgeConfig,
    "watchtower": WatchtowerConfig,
    "notify": NotifyConfig,
    "server": ServerConfig,
}


@dataclass
class Config:
    root: Path
    storage: StorageConfig = field(default_factory=StorageConfig)
    moat: MoatConfig = field(default_factory=MoatConfig)
    judge: JudgeConfig = field(default_factory=JudgeConfig)
    watchtower: WatchtowerConfig = field(default_factory=WatchtowerConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    server: ServerConfig = field(default_factory=ServerConfig)

    @property
    def state_dir(self) -> Path:
        return self.root / STATE_DIR

    @property
    def db_path(self) -> Path:
        return self.state_dir / "castle.db"

    @property
    def secrets_path(self) -> Path:
        return self.state_dir / "secrets.json"

    @property
    def quarantine_dir(self) -> Path:
        return self.state_dir / "quarantine"

    @property
    def realm_path(self) -> Path:
        realm = Path(self.storage.realm)
        return realm if realm.is_absolute() else self.root / realm


def load_config(root: Path | str) -> Config:
    root = Path(root).resolve()
    config = Config(root=root)
    path = root / CONFIG_FILE
    if not path.exists():
        return config
    try:
        data = tomllib.loads(path.read_text("utf-8-sig"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    for section, values in data.items():
        if section not in SECTIONS or not isinstance(values, dict):
            raise ConfigError(f"{path}: unknown section [{section}]")
        target = getattr(config, section)
        known = {f.name for f in fields(target)}
        for key, value in values.items():
            if key not in known:
                raise ConfigError(f"{path}: unknown key '{key}' in [{section}]")
            expected = type(getattr(target, key))
            if not isinstance(value, expected):
                raise ConfigError(
                    f"{path}: [{section}] {key} must be of type {expected.__name__}"
                )
            setattr(target, key, value)
    return config


def render_config(config: Config) -> str:
    """Render a commented redcastle.toml holding the given settings."""
    s, m, j, w, srv = config.storage, config.moat, config.judge, config.watchtower, config.server
    n = config.notify
    q = json.dumps  # JSON strings, numbers and string lists are valid TOML
    lines = [
        "# Red Castle configuration",
        "",
        "[storage]",
        '# "local" = a folder on disk, "s3" = an S3 bucket',
        f"backend = {q(s.backend)}",
        "# local: the folder the agents can see and ask to delete from",
        f"realm = {q(s.realm)}",
        "# s3: bucket, optional key prefix for the realm, and where quarantined objects hide",
        f"bucket = {q(s.bucket)}",
        f"prefix = {q(s.prefix)}",
        f"quarantine_prefix = {q(s.quarantine_prefix)}",
        f"region = {q(s.region)}",
        "# AWS profile for the castle, and a separate one that only the Executioner uses",
        f"profile = {q(s.profile)}",
        f"executioner_profile = {q(s.executioner_profile)}",
        "",
        "[moat]",
        "# Guardrails checked before anything else",
        f"max_requests_per_minute = {m.max_requests_per_minute}",
        f"max_requests_per_day = {m.max_requests_per_day}",
        f"min_reason_length = {m.min_reason_length}",
        "# Objects matching these patterns can never be deleted ('*' also crosses folders)",
        f"protected_patterns = {q(m.protected_patterns)}",
        "",
        "[judge]",
        "# A request is flagged when the Judge's score differs from the agent's by this much",
        f"discrepancy_threshold = {j.discrepancy_threshold}",
        f"burst_window_minutes = {j.burst_window_minutes}",
        f"burst_threshold = {j.burst_threshold}",
        "",
        "[judge.sensitive_patterns]",
        "# pattern = risk points added when the object key matches",
        *(f"{q(k)} = {v}" for k, v in j.sensitive_patterns.items()),
        "",
        "[judge.low_value_patterns]",
        *(f"{q(k)} = {v}" for k, v in j.low_value_patterns.items()),
        "",
        "[watchtower]",
        "# An agent is frozen automatically after this many underestimated risk scores...",
        f"underestimate_limit = {w.underestimate_limit}",
        f"underestimate_window_minutes = {w.underestimate_window_minutes}",
        "# ...or this many requests rejected by the Moat",
        f"rejection_limit = {w.rejection_limit}",
        f"rejection_window_minutes = {w.rejection_window_minutes}",
        "# How often the running castle patrols canaries, quarantine and the Chronicle (0 = never)",
        f"patrol_interval_seconds = {w.patrol_interval_seconds}",
        "# Optional URL that receives warning/critical alerts as JSON POSTs",
        f"webhook_url = {q(w.webhook_url)}",
        "",
        "[notify]",
        "# Desktop notifications when something needs a human",
        f"enabled = {q(n.enabled)}",
        "# Notify when an object lands in quarantine and awaits your judgement",
        f"on_quarantine = {q(n.on_quarantine)}",
        '# Notify about Watchtower alerts at or above this level: "warning" or "critical"',
        f"min_severity = {q(n.min_severity)}",
        "# Gather everything that happens within this many seconds into one notification",
        f"batch_seconds = {n.batch_seconds}",
        "# Remind you about undecided cases this often (0 = never)",
        f"remind_interval_minutes = {n.remind_interval_minutes}",
        "",
        "[server]",
        f"host = {q(srv.host)}",
        f"port = {srv.port}",
    ]
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Secrets:
    chronicle_key: bytes
    seal_key: bytes


def _parse_secrets(data: dict) -> Secrets:
    return Secrets(
        chronicle_key=bytes.fromhex(data["chronicle_key"]),
        seal_key=bytes.fromhex(data["seal_key"]),
    )


def create_secrets(path: Path) -> Secrets:
    """Generate the castle's keys."""
    if path.exists():
        raise ConfigError(f"{path} already exists - refusing to overwrite the castle's keys.")
    data = {"chronicle_key": _secrets.token_hex(32), "seal_key": _secrets.token_hex(32)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), "utf-8")
    return _parse_secrets(data)


def load_secrets(path: Path) -> Secrets:
    if not path.exists():
        raise ConfigError(f"No castle here ({path} is missing). Run 'redcastle init' first.")
    return _parse_secrets(json.loads(path.read_text("utf-8")))
