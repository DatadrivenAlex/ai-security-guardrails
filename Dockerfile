FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN useradd --create-home --uid 10001 appuser

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY policies ./policies

RUN pip install --no-cache-dir .

USER appuser

ENV GUARDRAILS_POLICY_PATH=/app/policies/default.yaml \
    GUARDRAILS_LOG_JSON=true \
    GUARDRAILS_LOG_PROMPTS=false \
    GUARDRAILS_HOST=0.0.0.0 \
    GUARDRAILS_PORT=8000

EXPOSE 8000

CMD ["uvicorn", "guardrails.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
