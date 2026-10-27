"""Operator denylist compiled from the policy file."""

import re

from guardrails.core.detectors.base import ScanContext, clip
from guardrails.core.models import Decision, Finding, Severity
from guardrails.core.policy import DenylistRule


class DenylistDetector:
    name = "denylist"

    def __init__(self, rules: list[DenylistRule]) -> None:
        self._compiled: list[tuple[DenylistRule, re.Pattern[str]]] = [
            (rule, re.compile(rule.pattern)) for rule in rules
        ]

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule, pattern in self._compiled:
            if ctx.direction not in rule.applies_to:
                continue
            for index, match in enumerate(pattern.finditer(ctx.text)):
                if index >= 5:
                    break
                severity = rule.severity
                action = (
                    Decision.DENY
                    if severity in {Severity.HIGH, Severity.CRITICAL}
                    else Decision.REWRITE
                )
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=severity,
                        title=f"Denylist:{rule.id}",
                        detail=rule.reason.strip(),
                        evidence=clip(match.group()),
                        owasp_id=rule.owasp_id,
                        suggested_action=action,
                        span_start=match.start(),
                        span_end=match.end(),
                    )
                )
        return findings
