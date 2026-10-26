"""The Judge: calculates its own risk score and compares it with the agent's."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .config import JudgeConfig
from .registry import Registry
from .storage import ObjectInfo
from .util import glob_match, now

MB = 1_000_000
LEVELS = ((30, "low"), (60, "medium"), (85, "high"), (101, "critical"))


def risk_level(score: int) -> str:
    return next(name for limit, name in LEVELS if score < limit)


@dataclass
class Verdict:
    score: int
    level: str
    agent_score: int
    discrepancy: int    # the Judge's score minus the agent's
    flag: str | None    # "underestimated", "overestimated" or None
    factors: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class Judge:
    BASE = 10

    def __init__(self, config: JudgeConfig, registry: Registry) -> None:
        self.config = config
        self.registry = registry

    def evaluate(
        self,
        *,
        agent: str,
        key: str,
        reason: str,
        agent_score: int,
        info: ObjectInfo,
        at: float | None = None,
    ) -> Verdict:
        at = now() if at is None else at
        factors: list[dict] = []

        def weigh(points: int, why: str) -> None:
            if points:
                factors.append({"points": points, "why": why})

        weigh(self.BASE, "permanent deletion is never risk-free")
        for pattern, points in self.config.sensitive_patterns.items():
            if glob_match(key, pattern):
                weigh(points, f"path matches sensitive pattern '{pattern}'")
        for pattern, points in self.config.low_value_patterns.items():
            if glob_match(key, pattern):
                weigh(points, f"path matches low-value pattern '{pattern}'")

        if info.size >= 100 * MB:
            weigh(20, "very large object (100 MB or more)")
        elif info.size >= 10 * MB:
            weigh(10, "large object (10 MB or more)")
        elif info.size >= MB:
            weigh(5, "object of 1 MB or more")
        elif info.size == 0:
            weigh(-5, "empty object")

        age = at - info.modified
        if age < 3600:
            weigh(15, "modified within the last hour - probably in active use")
        elif age < 86400:
            weigh(5, "modified within the last day")

        window = self.config.burst_window_minutes
        recent = self.registry.count_requests(agent, at - window * 60)
        if recent >= self.config.burst_threshold:
            weigh(15, f"agent sent {recent} requests in the last {window} minutes")
        past = self.registry.count_flags(agent, "underestimated", at - 7 * 86400)
        if past:
            weigh(min(20, 5 * past), f"agent underestimated the risk {past} time(s) in the last 7 days")
        if len(reason.strip()) < 25:
            weigh(5, "terse justification")

        score = max(0, min(100, sum(f["points"] for f in factors)))
        discrepancy = score - agent_score
        threshold = self.config.discrepancy_threshold
        if discrepancy >= threshold:
            flag = "underestimated"
        elif -discrepancy >= threshold:
            flag = "overestimated"
        else:
            flag = None
        return Verdict(score, risk_level(score), agent_score, discrepancy, flag, factors)
