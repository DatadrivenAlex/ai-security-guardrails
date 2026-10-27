"""Encoded and obfuscated payloads that decode to an injection phrase.

Covered transforms, all local and deterministic:

- base64 blobs
- hex dumps of ASCII text
- zero-width and bidi characters inserted into a phrase
- a small Cyrillic/Latin homoglyph map
- ROT13 over the whole text

A decoded blob is reported only when it matches an instruction-override, jailbreak,
or role-play rule. Benign base64 such as an encoded sentence about geography is ignored.
"""

import base64
import binascii
import codecs
import re

from guardrails.core.detectors.base import ScanContext, clip
from guardrails.core.detectors.injection import (
    INSTRUCTION_RULES,
    JAILBREAK_RULES,
    ROLEPLAY_RULES,
    Rule,
    hits,
)
from guardrails.core.models import Decision, Finding, Severity

_ATTACK_RULES: tuple[Rule, ...] = INSTRUCTION_RULES + JAILBREAK_RULES + ROLEPLAY_RULES
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])")
_ZERO_WIDTH = dict.fromkeys(
    map(
        ord,
        "\u200b\u200c\u200d\u200e\u200f\ufeff\u2060\u202a\u202b\u202c\u202d\u202e",
    )
)
_HOMOGLYPHS = str.maketrans(
    {
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0443": "y",
        "\u0445": "x",
        "\u0456": "i",
        "\u0455": "s",
        "\u0410": "A",
        "\u0415": "E",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0406": "I",
    }
)


def _printable(value: str) -> bool:
    if not value.strip():
        return False
    letters = sum(character.isprintable() for character in value)
    return letters / len(value) >= 0.9


def _decode_base64(token: str) -> str | None:
    if len(token) > 2_000:
        return None
    padded = token + ("=" * ((4 - len(token) % 4) % 4))
    try:
        raw = base64.b64decode(padded, validate=True)
    except (ValueError, binascii.Error):
        return None
    if not raw or len(raw) > 4_000:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not _printable(text):
        return None
    return text


def _decode_hex(token: str) -> str | None:
    if len(token) > 4_000:
        return None
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not _printable(text):
        return None
    return text


class EncodedPayloadDetector:
    name = "encoded_payload"

    def detect(self, ctx: ScanContext) -> list[Finding]:
        found: list[Finding] = []
        found.extend(self._encoded_blobs(ctx.text))
        found.extend(self._obfuscated_plain(ctx.text))
        return found[:8]

    def _encoded_blobs(self, text: str) -> list[Finding]:
        found: list[Finding] = []
        candidates: list[tuple[str, str, int, int]] = []
        for match in _B64_RE.finditer(text):
            decoded = _decode_base64(match.group(1))
            if decoded:
                candidates.append(("base64", decoded, match.start(1), match.end(1)))
            if len(candidates) >= 12:
                break
        for match in _HEX_RE.finditer(text):
            decoded = _decode_hex(match.group())
            if decoded:
                candidates.append(("hex", decoded, match.start(), match.end()))
            if len(candidates) >= 20:
                break
        for kind, decoded, start, end in candidates:
            decoded_hits = hits(decoded, _ATTACK_RULES, detector=self.name, limit=1)
            if not decoded_hits:
                continue
            found.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title=f"{kind} payload decodes to an injection phrase",
                    detail=(
                        "A blob decodes to text that matches an instruction-override, "
                        "jailbreak, or role-play rule. The decoded evidence is clipped."
                    ),
                    evidence=clip(f"{kind}: {decoded_hits[0].evidence}"),
                    owasp_id="LLM01",
                    suggested_action=Decision.DENY,
                    span_start=start,
                    span_end=end,
                )
            )
        return found

    def _obfuscated_plain(self, text: str) -> list[Finding]:
        found: list[Finding] = []
        stripped = text.translate(_ZERO_WIDTH)
        if stripped != text and hits(stripped, _ATTACK_RULES, detector=self.name, limit=1):
            found.append(
                self._obfuscation("zero-width or bidi characters hide an injection phrase")
            )
        folded = text.translate(_HOMOGLYPHS)
        original_hits = hits(text, _ATTACK_RULES, detector=self.name, limit=1)
        if (
            folded != text
            and not original_hits
            and hits(folded, _ATTACK_RULES, detector=self.name, limit=1)
        ):
            found.append(self._obfuscation("homoglyphs hide an injection phrase"))
        rotated = codecs.decode(text, "rot_13")
        if (
            rotated.casefold() != text.casefold()
            and not original_hits
            and hits(rotated, _ATTACK_RULES, detector=self.name, limit=1)
        ):
            found.append(self._obfuscation("ROT13 hides an injection phrase"))
        return found

    def _obfuscation(self, title: str) -> Finding:
        return Finding(
            detector=self.name,
            severity=Severity.HIGH,
            title=title,
            detail=(
                "The text matches an injection rule only after a reversible de-obfuscation step."
            ),
            evidence=title,
            owasp_id="LLM01",
            suggested_action=Decision.DENY,
        )
