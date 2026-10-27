"""Deterministic PII and secret span finders shared by inspect and sanitize."""

import re
from dataclasses import dataclass

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(
    r"(?<!\w)(?:"
    r"\+\d{1,3}[\s.\-]?\d{2,4}[\s.\-]\d{3,4}[\s.\-]\d{3,4}"
    r"|"
    r"\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}"
    r"|"
    r"\d{3}[\s.\-]\d{3}[\s.\-]\d{4}"
    r")(?!\w)"
)
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}\s?[A-Z0-9]{1,4}\b")
CARD_RE = re.compile(r"(?<!\d)(?:\d{4}[\s.\-]?){3}\d{1,7}(?!\d)")

# Well-known credential shapes. These are indicators, not proof of a live secret.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "high"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "high"),
    ("openai_project_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"), "high"),
    (
        "generic_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}['\"]?"
        ),
        "high",
    ),
)

PII_TYPES = ("email", "phone", "iban", "credit_card")
_PII_PRIORITY = {"credit_card": 4, "iban": 3, "email": 2, "phone": 1}


@dataclass(frozen=True)
class EntitySpan:
    entity_type: str
    start: int
    end: int
    value: str
    severity: str = "medium"


def luhn_ok(number: str) -> bool:
    """Return True when ``number`` (digits only) satisfies the Luhn check."""

    if not number.isdigit() or not 13 <= len(number) <= 19:
        return False
    total = 0
    for index, character in enumerate(reversed(number)):
        digit = int(character)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def iban_ok(value: str) -> bool:
    """ISO 13616 mod-97 check. A pattern match alone is not treated as an IBAN."""

    compact = re.sub(r"\s+", "", value).upper()
    if not 15 <= len(compact) <= 34:
        return False
    if not compact[:2].isalpha() or not compact[2:4].isdigit() or not compact.isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(int(character, 36)) for character in rearranged)
    return int(digits) % 97 == 1


def _overlaps(left: EntitySpan, right: EntitySpan) -> bool:
    return not (left.end <= right.start or left.start >= right.end)


def _select(spans: list[EntitySpan]) -> list[EntitySpan]:
    ordered = sorted(spans, key=lambda span: (-_PII_PRIORITY.get(span.entity_type, 0), span.start))
    chosen: list[EntitySpan] = []
    for span in ordered:
        if any(_overlaps(span, existing) for existing in chosen):
            continue
        chosen.append(span)
    chosen.sort(key=lambda span: span.start)
    return chosen


def find_pii(text: str, entity_types: set[str] | None = None) -> list[EntitySpan]:
    """Find non-overlapping PII spans. Credit-card and IBAN hits must checksum."""

    wanted = set(PII_TYPES) if entity_types is None else set(entity_types)
    unknown = wanted - set(PII_TYPES)
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ValueError(f"unknown entity type: {names}")

    found: list[EntitySpan] = []
    if "email" in wanted:
        for match in EMAIL_RE.finditer(text):
            found.append(
                EntitySpan("email", match.start(), match.end(), match.group(), severity="low")
            )
    if "phone" in wanted:
        for match in PHONE_RE.finditer(text):
            value = match.group()
            digits = re.sub(r"\D", "", value)
            if 10 <= len(digits) <= 15:
                found.append(EntitySpan("phone", match.start(), match.end(), value, severity="low"))
    if "iban" in wanted:
        for match in IBAN_RE.finditer(text):
            value = match.group()
            if iban_ok(value):
                found.append(
                    EntitySpan("iban", match.start(), match.end(), value, severity="medium")
                )
    if "credit_card" in wanted:
        for match in CARD_RE.finditer(text):
            value = match.group()
            digits = re.sub(r"\D", "", value)
            if luhn_ok(digits):
                found.append(
                    EntitySpan("credit_card", match.start(), match.end(), value, severity="medium")
                )
    return _select(found)


def find_secrets(text: str) -> list[EntitySpan]:
    found: list[EntitySpan] = []
    for name, pattern, severity in SECRET_PATTERNS:
        for index, match in enumerate(pattern.finditer(text)):
            if index >= 8:
                break
            found.append(EntitySpan(name, match.start(), match.end(), match.group(), severity))
    return _select_any(found)


def _select_any(spans: list[EntitySpan]) -> list[EntitySpan]:
    """Drop overlapping secret hits, keeping the earlier and then the longer one."""

    ordered = sorted(spans, key=lambda span: (span.start, -(span.end - span.start)))
    chosen: list[EntitySpan] = []
    for span in ordered:
        if any(_overlaps(span, existing) for existing in chosen):
            continue
        chosen.append(span)
    return chosen


def mask_span(entity_type: str, value: str) -> str:
    """Short evidence string that does not repeat the raw value."""

    if entity_type == "email" and "@" in value:
        name, _, domain = value.partition("@")
        return f"{name[:1]}…@{domain}"
    if entity_type in {"credit_card", "phone"}:
        digits = re.sub(r"\D", "", value)
        tail = digits[-4:] if len(digits) >= 4 else "????"
        return f"***{tail}"
    if entity_type == "iban":
        compact = re.sub(r"\s+", "", value)
        if len(compact) >= 6:
            return f"{compact[:2]}…{compact[-4:]}"
    compact = re.sub(r"\s+", "", value)
    if len(compact) <= 8:
        return "***"
    return f"{compact[:4]}…{compact[-2:]} ({len(compact)} chars)"
