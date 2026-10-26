"""The Moat: guardrails every request must cross before anyone judges it."""

from __future__ import annotations

from .config import MoatConfig
from .registry import Registry
from .storage import InvalidKey, normalize_key
from .util import glob_match, now


class MoatViolation(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class Moat:
    def __init__(self, config: MoatConfig, registry: Registry) -> None:
        self.config = config
        self.registry = registry

    def check_agent(self, agent: dict) -> None:
        if agent["status"] != "active":
            raise MoatViolation(
                "agent_frozen",
                "This agent is frozen by the Throne Room and may not submit deletion requests.",
            )

    def check_form(self, key: object, reason: object, risk_score: object) -> tuple[str, int]:
        """Validate the request's shape. Returns the normalized key and score."""
        try:
            key = normalize_key(key)
        except InvalidKey as exc:
            raise MoatViolation("invalid_key", str(exc)) from exc
        minimum = self.config.min_reason_length
        if not isinstance(reason, str) or len(reason.strip()) < minimum:
            raise MoatViolation(
                "reason_required", f"Explain why the object should be deleted (at least {minimum} characters)."
            )
        if len(reason) > 2000:
            raise MoatViolation("reason_too_long", "The reason must be at most 2000 characters.")
        if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)) or not 0 <= risk_score <= 100:
            raise MoatViolation(
                "invalid_risk_score",
                "risk_score must be a number from 0 to 100: your own estimate of how risky this deletion is.",
            )
        return key, int(round(risk_score))

    def check_limits(self, agent: str, key: str) -> None:
        for pattern in self.config.protected_patterns:
            if glob_match(key, pattern):
                raise MoatViolation(
                    "protected_object", f"'{key}' is protected by the Moat and can never be deleted."
                )
        # The current request is already recorded, hence '>' rather than '>='.
        t = now()
        if self.registry.count_requests(agent, t - 60) > self.config.max_requests_per_minute:
            raise MoatViolation(
                "rate_limited",
                f"At most {self.config.max_requests_per_minute} deletion requests per minute.",
            )
        if self.registry.count_requests(agent, t - 86400) > self.config.max_requests_per_day:
            raise MoatViolation(
                "daily_limit", f"At most {self.config.max_requests_per_day} deletion requests per day."
            )
