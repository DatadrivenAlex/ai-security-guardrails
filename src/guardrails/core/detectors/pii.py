"""PII findings. Suggested action is rewrite, not deny."""

from guardrails.core.detectors.base import ScanContext
from guardrails.core.entities import find_pii, mask_span
from guardrails.core.models import Decision, Finding, Severity

_SEVERITY = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH}
_DETAIL = {
    "email": "Email address. Inspect rewrites it; use /v1/sanitize for a token map.",
    "phone": "Phone number. Inspect rewrites it; use /v1/sanitize for a token map.",
    "iban": "String that passes the IBAN mod-97 check.",
    "credit_card": "Number that passes the Luhn check and looks like a payment card.",
}


class PiiDetector:
    name = "pii"

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for span in find_pii(ctx.text):
            findings.append(
                Finding(
                    detector=self.name,
                    severity=_SEVERITY[span.severity],
                    title=f"PII ({span.entity_type})",
                    detail=_DETAIL[span.entity_type],
                    evidence=mask_span(span.entity_type, span.value),
                    owasp_id="LLM02",
                    suggested_action=Decision.REWRITE,
                    entity_type=span.entity_type,
                    span_start=span.start,
                    span_end=span.end,
                )
            )
        return findings
