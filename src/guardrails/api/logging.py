"""JSON logs on stdout. Prompt bodies stay out of the log unless explicitly enabled."""

import hashlib
import logging

import structlog

from guardrails.config import Settings


def configure_logging(settings: Settings) -> None:
    level_name = settings.log_level.upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(format="%(message)s", level=level, force=True)
    renderer: structlog.types.Processor
    if settings.log_json:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


def text_fingerprint(text: str) -> dict[str, int | str]:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return {"text_sha256": digest, "text_len": len(text)}


def get_logger() -> structlog.stdlib.BoundLogger:
    return structlog.get_logger("guardrails")
