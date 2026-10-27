"""Prometheus metrics on a private registry so tests can create many apps."""

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

from guardrails.core.models import Direction, InspectionResult

CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.inspections = Counter(
            "guardrails_inspections_total",
            "Inspect calls by direction and decision.",
            labelnames=("direction", "decision"),
            registry=self.registry,
        )
        self.findings = Counter(
            "guardrails_detector_findings_total",
            "Findings by detector and severity.",
            labelnames=("detector", "severity"),
            registry=self.registry,
        )
        self.redactions = Counter(
            "guardrails_sanitize_redactions_total",
            "Sanitize replacements by entity type.",
            labelnames=("entity_type",),
            registry=self.registry,
        )
        self.risk_score = Histogram(
            "guardrails_inspection_risk_score",
            "Inspect risk score.",
            registry=self.registry,
            buckets=(0, 15, 35, 60, 85, 100),
        )

    def record_inspection(self, result: InspectionResult, direction: Direction) -> None:
        self.inspections.labels(direction=direction.value, decision=result.decision.value).inc()
        self.risk_score.observe(result.risk_score)
        for finding in result.findings:
            self.findings.labels(detector=finding.detector, severity=finding.severity.value).inc()

    def record_redactions(self, entity_types: list[str]) -> None:
        for entity_type in entity_types:
            self.redactions.labels(entity_type=entity_type).inc()

    def render(self) -> bytes:
        return generate_latest(self.registry)
