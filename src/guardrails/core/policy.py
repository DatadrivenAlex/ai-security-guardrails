"""Load an operator policy from YAML or JSON. Policies are trusted configuration."""

import json
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from guardrails.core.models import Direction, Severity


class PolicyError(Exception):
    """The policy file is missing or does not match the schema."""


class Thresholds(BaseModel):
    deny: float = Field(default=70, ge=0, le=100)
    rewrite: float = Field(default=25, ge=0, le=100)


class DetectorConfig(BaseModel):
    enabled: bool = True
    weight: float = Field(default=1.0, ge=0, le=5)


class DenylistRule(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    pattern: str = Field(min_length=1, max_length=300)
    severity: Severity = Severity.HIGH
    reason: str = Field(min_length=1, max_length=400)
    owasp_id: str = "LLM01"
    applies_to: list[Direction] = Field(
        default_factory=lambda: [Direction.PROMPT, Direction.COMPLETION]
    )

    @field_validator("pattern")
    @classmethod
    def _compile_pattern(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid regular expression: {exc}") from exc
        return value


class AllowlistConfig(BaseModel):
    substrings: list[str] = Field(default_factory=list)


class Policy(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    version: int = 1
    description: str = ""
    thresholds: Thresholds = Field(default_factory=Thresholds)
    detectors: dict[str, DetectorConfig] = Field(default_factory=dict)
    denylist: list[DenylistRule] = Field(default_factory=list, max_length=100)
    allowlist: AllowlistConfig = Field(default_factory=AllowlistConfig)
    echo_min_chars: int = Field(default=48, ge=16, le=500)

    @model_validator(mode="after")
    def _threshold_order(self) -> "Policy":
        if self.thresholds.rewrite > self.thresholds.deny:
            raise ValueError("rewrite threshold cannot exceed deny threshold")
        return self

    def detector_enabled(self, name: str) -> bool:
        config = self.detectors.get(name)
        if config is None:
            return True
        return config.enabled

    def weight_for(self, name: str) -> float:
        config = self.detectors.get(name)
        if config is None:
            return 1.0
        return config.weight


def load_policy(path: Path) -> Policy:
    """Read YAML or JSON. Raises ``PolicyError`` for I/O and schema problems."""

    if not path.is_file():
        raise PolicyError(f"policy file not found: {path}")
    raw_text = path.read_text(encoding="utf-8")
    try:
        if path.suffix.lower() == ".json":
            raw = json.loads(raw_text)
        else:
            raw = yaml.safe_load(raw_text)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise PolicyError(f"policy file is not valid YAML or JSON: {path}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"policy root must be a mapping: {path}")
    try:
        return Policy.model_validate(raw)
    except ValueError as exc:
        raise PolicyError(f"policy schema error in {path}: {exc}") from exc
