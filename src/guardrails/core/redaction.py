"""Replace PII spans with stable placeholders such as ``[EMAIL_1]``."""

from guardrails.core.entities import EntitySpan
from guardrails.core.models import Redaction


def redact(
    text: str,
    spans: list[EntitySpan],
    *,
    reversible: bool,
) -> tuple[str, list[Redaction], dict[str, str] | None]:
    """Apply non-overlapping spans from left to right.

    Token numbers restart at 1 for each entity type. When ``reversible`` is true the
    returned map restores the original substring. Callers must treat that map as
    sensitive; this function does not store it.
    """

    ordered = sorted(spans, key=lambda span: span.start)
    counters: dict[str, int] = {}
    pieces: list[str] = []
    redactions: list[Redaction] = []
    token_map: dict[str, str] = {}
    cursor = 0
    for span in ordered:
        if span.start < cursor:
            continue
        pieces.append(text[cursor : span.start])
        counters[span.entity_type] = counters.get(span.entity_type, 0) + 1
        label = span.entity_type.upper()
        token = f"[{label}_{counters[span.entity_type]}]"
        pieces.append(token)
        redactions.append(
            Redaction(
                entity_type=span.entity_type,
                token=token,
                start=span.start,
                end=span.end,
                original=span.value if reversible else None,
            )
        )
        if reversible:
            token_map[token] = span.value
        cursor = span.end
    pieces.append(text[cursor:])
    rendered = "".join(pieces)
    return rendered, redactions, (token_map if reversible else None)
