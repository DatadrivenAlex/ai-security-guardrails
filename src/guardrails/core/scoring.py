"""Turn findings into a 0-100 score and an allow / deny / rewrite decision.

The score is a weighted sum of severity points. It is a ranking signal for humans
and dashboards. The decision itself follows each finding's suggested action so a
single critical jailbreak cannot be averaged away, and ordinary PII is redacted
instead of blocked.
"""

from guardrails.core.models import Decision, Finding, Severity
from guardrails.core.policy import Policy

SEVERITY_POINTS: dict[Severity, float] = {
    Severity.INFO: 0,
    Severity.LOW: 15,
    Severity.MEDIUM: 35,
    Severity.HIGH: 60,
    Severity.CRITICAL: 85,
}


def score_findings(findings: list[Finding], policy: Policy) -> float:
    total = 0.0
    for finding in findings:
        total += SEVERITY_POINTS[finding.severity] * policy.weight_for(finding.detector)
    return round(min(100.0, total), 1)


def decide(findings: list[Finding], score: float, policy: Policy) -> Decision:
    """Apply the policy decision rules.

    1. No findings -> allow.
    2. Any finding that suggests deny -> deny. A high score is not required.
    3. Otherwise any rewrite finding, or a score at or above the rewrite threshold, -> rewrite.
    4. A score at or above the deny threshold also denies when the findings are not
       exclusively rewrite-class (PII). A PII-only result stays a rewrite so the
       caller receives redacted text instead of a hard block.
    """

    if not findings:
        return Decision.ALLOW
    if any(finding.suggested_action is Decision.DENY for finding in findings):
        return Decision.DENY
    rewrite_only = all(finding.suggested_action is Decision.REWRITE for finding in findings)
    if score >= policy.thresholds.deny and not rewrite_only:
        return Decision.DENY
    if any(finding.suggested_action is Decision.REWRITE for finding in findings):
        return Decision.REWRITE
    if score >= policy.thresholds.rewrite:
        return Decision.REWRITE
    return Decision.ALLOW


def summarize(decision: Decision, findings: list[Finding], score: float) -> str:
    if decision is Decision.ALLOW:
        return f"Allowed. Risk score {score:.1f}."
    names = list(dict.fromkeys(finding.detector for finding in findings))
    joined = ", ".join(names[:4])
    verb = "Denied" if decision is Decision.DENY else "Rewrite recommended"
    return f"{verb} by {joined}. Risk score {score:.1f}."
