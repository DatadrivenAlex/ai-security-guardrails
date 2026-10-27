"""``python -m guardrails`` starts the HTTP service."""

from guardrails.config import Settings


def main() -> None:
    import uvicorn

    settings = Settings()
    uvicorn.run(
        "guardrails.api.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
