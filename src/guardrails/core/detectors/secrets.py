"""Secret-shaped strings in prompts or completions (OWASP LLM02 / LLM07)."""

from guardrails.core.detectors.base import ScanContext
from guardrails.core.entities import find_secrets, mask_span
from guardrails.core.models import Decision, Finding, Severity

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}
_TITLES = {
    "aws_access_key": "Cloud access key id",
    "private_key": "Private key header",
    "github_token": "GitHub token shape",
    "slack_token": "Slack token shape",
    "openai_project_key": "Model API key shape",
    "generic_assignment": "Generic secret assignment",
}


class SecretLeakDetector:
    name = "secret_leak"

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for span in find_secrets(ctx.text):
            findings.append(
                Finding(
                    detector=self.name,
                    severity=_SEVERITY[span.severity],
                    title=_TITLES.get(span.entity_type, "Secret-shaped string"),
                    detail=(
                        "The text contains a string shaped like a credential. "
                        "This is a pattern match, not a check that the credential works."
                    ),
                    evidence=mask_span(span.entity_type, span.value),
                    owasp_id="LLM02",
                    suggested_action=Decision.DENY,
                    entity_type=span.entity_type,
                    span_start=span.start,
                    span_end=span.end,
                )
            )
        return findings
