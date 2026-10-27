"""Process settings. Environment variables use the ``GUARDRAILS_`` prefix."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def default_policy_path() -> Path:
    """Prefer ``./policies/default.yaml``, then the copy next to an editable checkout."""

    cwd_candidate = Path.cwd() / "policies" / "default.yaml"
    if cwd_candidate.is_file():
        return cwd_candidate
    checkout = Path(__file__).resolve().parents[2] / "policies" / "default.yaml"
    return checkout


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GUARDRAILS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    policy_path: Path = Field(default_factory=default_policy_path)
    log_level: str = "INFO"
    log_json: bool = True
    log_prompts: bool = False
    host: str = "127.0.0.1"
    port: int = 8000
