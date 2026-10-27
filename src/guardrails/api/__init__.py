"""HTTP adapter. The rules engine does not import this package."""

from guardrails.api.app import create_app

__all__ = ["create_app"]
