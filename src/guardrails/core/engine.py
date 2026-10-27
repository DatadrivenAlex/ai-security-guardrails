"""Rules engine. Orchestrates detectors, allowlist suppression, score, and rewrite."""

from guardrails.core.detectors import build_detectors
from guardrails.core.detectors.base import ScanContext
from guardrails.core.entities import PII_TYPES, EntitySpan, find_pii
from guardrails.core.models import (
    Decision,
    Finding,
    InspectionRequest,
    InspectionResult,
    SanitizeRequest,
    SanitizeResult,
)
from guardrails.core.policy import Policy
from guardrails.core.redaction import redact
from guardrails.core.scoring import decide, score_findings, summarize


class PolicyMismatchError(Exception):
    def __init__(self, requested: str, loaded: str) -> None:
        self.requested = requested
        self.loaded = loaded
        super().__init__(f"policy '{requested}' is not loaded (loaded '{loaded}')")


class RulesEngine:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self._detectors = build_detectors(policy)

    def inspect(self, request: InspectionRequest) -> InspectionResult:
        if request.policy_id and request.policy_id != self.policy.id:
            raise PolicyMismatchError(request.policy_id, self.policy.id)
        context = ScanContext(
            text=request.text,
            direction=request.direction,
            system_prompt=request.system_prompt,
            policy=self.policy,
        )
        findings: list[Finding] = []
        for detector in self._detectors:
            if not self.policy.detector_enabled(detector.name):
                continue
            findings.extend(detector.detect(context))
        findings = [item for item in findings if not _allowlisted(request.text, item, self.policy)]
        findings = _dedupe(findings)[:50]
        score = score_findings(findings, self.policy)
        decision = decide(findings, score, self.policy)
        rewritten: str | None = None
        if decision is Decision.REWRITE:
            rewritten = _rewrite(request.text, findings)
        reasons = list(dict.fromkeys(item.title for item in findings))
        owasp_ids = list(dict.fromkeys(item.owasp_id for item in findings if item.owasp_id))
        return InspectionResult(
            decision=decision,
            risk_score=score,
            reasons=reasons,
            findings=findings,
            rewritten_text=rewritten,
            policy_id=self.policy.id,
            owasp_ids=owasp_ids,
            summary=summarize(decision, findings, score),
        )

    def sanitize(self, request: SanitizeRequest) -> SanitizeResult:
        types = set(request.entity_types) if request.entity_types else None
        try:
            spans = find_pii(request.text, types)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        text, redactions, token_map = redact(request.text, spans, reversible=request.reversible)
        return SanitizeResult(text=text, redactions=redactions, token_map=token_map)


def _allowlisted(text: str, finding: Finding, policy: Policy) -> bool:
    if finding.span_start is None or finding.span_end is None:
        return False
    haystack = text.casefold()
    for phrase in policy.allowlist.substrings:
        if not phrase:
            continue
        needle = phrase.casefold()
        start = 0
        while True:
            index = haystack.find(needle, start)
            if index < 0:
                break
            end = index + len(needle)
            if finding.span_start >= index and finding.span_end <= end:
                return True
            start = index + 1
    return False


def _overlaps(left: Finding, right: Finding) -> bool:
    if None in {left.span_start, left.span_end, right.span_start, right.span_end}:
        return False
    assert left.span_start is not None and left.span_end is not None
    assert right.span_start is not None and right.span_end is not None
    return not (left.span_end <= right.span_start or left.span_start >= right.span_end)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    kept: list[Finding] = []
    for finding in findings:
        if any(
            existing.detector == finding.detector
            and existing.title == finding.title
            and _overlaps(existing, finding)
            for existing in kept
        ):
            continue
        kept.append(finding)
    return kept


def _rewrite(text: str, findings: list[Finding]) -> str:
    spans: list[EntitySpan] = []
    for finding in findings:
        if finding.suggested_action is not Decision.REWRITE:
            continue
        if finding.span_start is None or finding.span_end is None:
            continue
        entity_type = finding.entity_type or finding.detector
        if entity_type not in PII_TYPES:
            entity_type = finding.detector
        spans.append(
            EntitySpan(
                entity_type=entity_type,
                start=finding.span_start,
                end=finding.span_end,
                value=text[finding.span_start : finding.span_end],
            )
        )
    rewritten, _, _ = redact(text, spans, reversible=False)
    return rewritten
