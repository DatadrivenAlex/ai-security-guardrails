"""FastAPI application factory.

The module-level ``app`` is what uvicorn loads. Tests should call ``create_app``
so they can pass a policy object and a private metrics registry.
"""

import uuid

import structlog.contextvars
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from guardrails import __version__
from guardrails.api.logging import configure_logging, get_logger, text_fingerprint
from guardrails.api.metrics import CONTENT_TYPE_LATEST, Metrics
from guardrails.config import Settings
from guardrails.core.engine import PolicyMismatchError, RulesEngine
from guardrails.core.models import (
    InspectionRequest,
    InspectionResult,
    SanitizeRequest,
    SanitizeResult,
)
from guardrails.core.policy import Policy, PolicyError, load_policy


def create_app(policy: Policy | None = None, settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings)
    if policy is None:
        try:
            policy = load_policy(settings.policy_path)
        except PolicyError as exc:
            raise RuntimeError(str(exc)) from exc
    engine = RulesEngine(policy)
    metrics = Metrics()
    log = get_logger()

    app = FastAPI(
        title="AI Security Guardrails",
        version=__version__,
        summary="Inspect prompts and completions before they reach or leave an LLM.",
        description=(
            "Pattern-based educational firewall for LLM prompts and completions. "
            "It is not a production WAF, SIEM, or zero-day detector. "
            "See the repository README and SECURITY.md for limits."
        ),
    )
    app.state.engine = engine
    app.state.settings = settings
    app.state.metrics = metrics
    app.state.log = log

    @app.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            path=request.url.path,
            method=request.method,
        )
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.clear_contextvars()
        response.headers["x-request-id"] = request_id
        return response

    @app.get("/", include_in_schema=False)
    def index() -> dict[str, str]:
        return {
            "service": "ai-security-guardrails",
            "version": __version__,
            "docs": "/docs",
            "health": "/health",
            "ready": "/ready",
            "metrics": "/metrics",
        }

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready", response_model=None)
    def ready() -> dict[str, str] | JSONResponse:
        path = settings.policy_path
        if not path.is_file():
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "reason": "policy file missing"},
            )
        return {"status": "ready", "policy_id": engine.policy.id}

    @app.get("/metrics")
    def metrics_endpoint() -> Response:
        return Response(content=metrics.render(), media_type=CONTENT_TYPE_LATEST)

    @app.post("/v1/inspect", response_model=InspectionResult)
    def inspect(body: InspectionRequest) -> InspectionResult:
        try:
            result = engine.inspect(body)
        except PolicyMismatchError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        metrics.record_inspection(result, body.direction)
        fields: dict[str, object] = {
            "direction": body.direction.value,
            "decision": result.decision.value,
            "risk_score": result.risk_score,
            "finding_count": len(result.findings),
            "detectors": sorted({item.detector for item in result.findings}),
            **text_fingerprint(body.text),
        }
        if settings.log_prompts:
            fields["text_preview"] = body.text[:200]
        log.info("inspection", **fields)
        return result

    @app.post("/v1/sanitize", response_model=SanitizeResult, response_model_exclude_none=True)
    def sanitize(body: SanitizeRequest) -> SanitizeResult:
        try:
            result = engine.sanitize(body)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        metrics.record_redactions([item.entity_type for item in result.redactions])
        fields = {
            "reversible": body.reversible,
            "redaction_count": len(result.redactions),
            "entity_types": sorted({item.entity_type for item in result.redactions}),
            **text_fingerprint(body.text),
        }
        if settings.log_prompts:
            fields["text_preview"] = body.text[:200]
        # The token map restores raw PII. It is never logged.
        log.info("sanitize", **fields)
        return result

    return app


app = create_app()
