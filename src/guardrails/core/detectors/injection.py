"""High-signal prompt-injection phrases.

These are heuristics for a demo and a regression suite. They are not a model of
attacker intent, and a paraphrase that avoids the phrases will not match.
"""

import re

from guardrails.core.detectors.base import ScanContext, clip
from guardrails.core.models import Decision, Finding, Severity

# (pattern, title, severity, detail)
Rule = tuple[re.Pattern[str], str, Severity, str]

_INSTRUCTION: tuple[tuple[str, str, Severity, str], ...] = (
    (
        r"\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|prompts?|rules?|guidelines?)\b",
        "Instruction override",
        Severity.CRITICAL,
        "The text tells the model to discard earlier or higher-priority instructions.",
    ),
    (
        r"\bignore\s+all\s+(?:previous\s+)?(?:instructions?|prompts?|rules?|guidelines?)\b",
        "Instruction override",
        Severity.CRITICAL,
        "The text tells the model to discard earlier or higher-priority instructions.",
    ),
    (
        r"\b(?:disregard|forget|override)\s+(?:all\s+|any\s+)?(?:your\s+|the\s+)?"
        r"(?:previous|prior|above|system|original)\s+(?:instructions?|prompts?|rules?|guidelines?)\b",
        "Instruction override",
        Severity.CRITICAL,
        "The text tells the model to discard its system or prior rules.",
    ),
    (
        r"\bdo\s+not\s+follow\s+(?:your\s+|the\s+)?(?:system|previous|original)\s+"
        r"(?:instructions?|rules?|prompt)\b",
        "Instruction override",
        Severity.CRITICAL,
        "The text tells the model not to follow its system or original instructions.",
    ),
    (
        r"\b(?:new|updated)\s+instructions?\s*:",
        "Replacement instruction block",
        Severity.HIGH,
        "The text introduces a replacement instruction block.",
    ),
)

_JAILBREAK: tuple[tuple[str, str, Severity, str], ...] = (
    (
        r"\bdo\s+anything\s+now\b",
        "Jailbreak phrase",
        Severity.CRITICAL,
        "Matches the well-known 'do anything now' jailbreak marker.",
    ),
    (
        r"\bdeveloper\s+mode\b",
        "Jailbreak phrase",
        Severity.HIGH,
        "Asks for a developer mode that ignores normal constraints.",
    ),
    (
        r"\bjail\s*break\b",
        "Jailbreak phrase",
        Severity.HIGH,
        "Names a jailbreak directly.",
    ),
    (
        r"\b(?:you\s+are\s+)?dan\s+mode\b|\byou\s+are\s+(?:now\s+)?dan\b",
        "Jailbreak phrase",
        Severity.HIGH,
        "Names the DAN jailbreak persona.",
    ),
    (
        r"\bbypass\b(?:\s+\w+){0,3}\s+\b(?:safety|filter|filters|guardrails?|restrictions|policy)\b",
        "Jailbreak phrase",
        Severity.HIGH,
        "Asks to bypass a safety filter, guardrail, or policy.",
    ),
    (
        r"\bwithout\s+(?:any\s+)?(?:safety\s+)?(?:restrictions|filters|safety\s+rules)\b",
        "Jailbreak phrase",
        Severity.HIGH,
        "Asks the model to answer without its usual restrictions.",
    ),
)

_ROLEPLAY: tuple[tuple[str, str, Severity, str], ...] = (
    (
        r"\b(?:pretend|act|role[\s\-]?play)\b(?:\s+\w+){0,6}\s+\b(?:as|that)\b"
        r"(?:\s+\w+){0,8}\s+\b(?:unrestricted|unfiltered|jailbroken|evil)\b",
        "Role-play escape",
        Severity.HIGH,
        (
            "Role-play framed as a way to drop safety constraints. "
            "Ordinary tutor prompts do not match."
        ),
    ),
    (
        r"\bfrom\s+now\s+on\b(?:\s+\w+){0,8}\s+\b(?:ignore|bypass|disregard)\b",
        "Role-play escape",
        Severity.HIGH,
        "A persona reset that leads into an instruction override.",
    ),
)


def _compile(rules: tuple[tuple[str, str, Severity, str], ...]) -> tuple[Rule, ...]:
    return tuple(
        (re.compile(pattern, re.IGNORECASE), title, severity, detail)
        for pattern, title, severity, detail in rules
    )


INSTRUCTION_RULES = _compile(_INSTRUCTION)
JAILBREAK_RULES = _compile(_JAILBREAK)
ROLEPLAY_RULES = _compile(_ROLEPLAY)


def hits(text: str, rules: tuple[Rule, ...], *, detector: str, limit: int = 5) -> list[Finding]:
    found: list[Finding] = []
    for pattern, title, severity, detail in rules:
        for match in pattern.finditer(text):
            found.append(
                Finding(
                    detector=detector,
                    severity=severity,
                    title=title,
                    detail=detail,
                    evidence=clip(match.group()),
                    owasp_id="LLM01",
                    suggested_action=Decision.DENY,
                    span_start=match.start(),
                    span_end=match.end(),
                )
            )
            if len(found) >= limit:
                return found
    return found


class InstructionOverrideDetector:
    name = "instruction_override"

    def detect(self, ctx: ScanContext) -> list[Finding]:
        return hits(ctx.text, INSTRUCTION_RULES, detector=self.name)


class JailbreakDetector:
    name = "jailbreak"

    def detect(self, ctx: ScanContext) -> list[Finding]:
        return hits(ctx.text, JAILBREAK_RULES, detector=self.name)


class RoleplayEscapeDetector:
    name = "roleplay_escape"

    def detect(self, ctx: ScanContext) -> list[Finding]:
        return hits(ctx.text, ROLEPLAY_RULES, detector=self.name)
