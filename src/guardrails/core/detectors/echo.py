"""System-prompt extraction attempts and completion echo (OWASP LLM07).

Echo detection compares a caller-supplied ``system_prompt`` with the completion.
The service does not know the real prompt unless the caller sends it. Overlap
uses whitespace-collapsed fragments of at least ``echo_min_chars`` so a short
generic prompt such as "be helpful" does not match.
"""

import re

from guardrails.core.detectors.base import ScanContext, clip
from guardrails.core.models import Decision, Direction, Finding, Severity

_EXTRACTION_RE = re.compile(
    r"\b(?:reveal|show|print|repeat|dump|leak)\b(?:\s+\w+){0,4}\s+"
    r"\b(?:your\s+|the\s+)?(?:system|hidden|initial|original)\s+(?:prompt|instructions?)\b",
    re.IGNORECASE,
)
_LEAK_CLAIM_RE = re.compile(
    r"\b(?:my|the)\s+(?:system|hidden|initial)\s+(?:prompt|instructions?)\s+(?:is|are|say|says)\b",
    re.IGNORECASE,
)


def _fragments(system_prompt: str, min_chars: int) -> list[str]:
    normalized = " ".join(system_prompt.split())
    if len(normalized) < min_chars:
        return []
    pieces = [normalized[: min(len(normalized), 180)]]
    if len(normalized) > min_chars + 80:
        middle = len(normalized) // 3
        pieces.append(normalized[middle : middle + 120])
    return [piece for piece in pieces if len(piece) >= min_chars]


class SystemPromptEchoDetector:
    name = "system_prompt_echo"

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for match in _EXTRACTION_RE.finditer(ctx.text):
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="System-prompt extraction attempt",
                    detail="The text asks the model to reveal its system or hidden prompt.",
                    evidence=clip(match.group()),
                    owasp_id="LLM07",
                    suggested_action=Decision.DENY,
                    span_start=match.start(),
                    span_end=match.end(),
                )
            )
            if len(findings) >= 3:
                break
        if ctx.direction is not Direction.COMPLETION:
            return findings
        if ctx.system_prompt:
            completion = " ".join(ctx.text.split()).casefold()
            for fragment in _fragments(ctx.system_prompt, ctx.policy.echo_min_chars):
                if fragment.casefold() in completion:
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity=Severity.CRITICAL,
                            title="Completion echoes the system prompt",
                            detail=(
                                "A long fragment of the caller-supplied system prompt "
                                "appears in the completion."
                            ),
                            evidence=clip(fragment, limit=60),
                            owasp_id="LLM07",
                            suggested_action=Decision.DENY,
                        )
                    )
                    break
        else:
            for match in _LEAK_CLAIM_RE.finditer(ctx.text):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.HIGH,
                        title="Completion claims to reveal hidden instructions",
                        detail=(
                            "No system prompt was supplied for an overlap check. "
                            "The completion still claims to quote hidden instructions."
                        ),
                        evidence=clip(match.group()),
                        owasp_id="LLM07",
                        suggested_action=Decision.DENY,
                        span_start=match.start(),
                        span_end=match.end(),
                    )
                )
                break
        return findings
