"""Detector protocol and scan context."""

from dataclasses import dataclass
from typing import Protocol

from guardrails.core.models import Direction, Finding
from guardrails.core.policy import Policy


@dataclass(frozen=True)
class ScanContext:
    text: str
    direction: Direction
    system_prompt: str | None
    policy: Policy


class Detector(Protocol):
    name: str

    def detect(self, ctx: ScanContext) -> list[Finding]:
        """Return zero or more findings. Must be deterministic and side-effect free."""


def clip(value: str, limit: int = 80) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"
