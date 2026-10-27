import pytest

from guardrails.core.entities import iban_ok, luhn_ok
from guardrails.core.models import SanitizeRequest


def test_luhn_and_iban_helpers():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")
    assert iban_ok("DE89 3704 0044 0532 0130 00")
    assert iban_ok("GB82WEST12345698765432")
    assert not iban_ok("DE00370400440532013000")


def test_sanitize_reversible_roundtrip(engine):
    original = "Mail ada@example.com or call +1 415 555 0134 about DE89370400440532013000."
    result = engine.sanitize(SanitizeRequest(text=original, reversible=True))
    assert result.token_map is not None
    restored = result.text
    for token, value in result.token_map.items():
        restored = restored.replace(token, value)
    assert restored == original
    assert "[EMAIL_1]" in result.text
    assert "[PHONE_1]" in result.text
    assert "[IBAN_1]" in result.text
    assert any(item.original == "ada@example.com" for item in result.redactions)


def test_sanitize_hides_original_when_not_reversible(engine):
    result = engine.sanitize(SanitizeRequest(text="Mail ada@example.com today.", reversible=False))
    assert result.token_map is None
    assert result.text == "Mail [EMAIL_1] today."
    assert all(item.original is None for item in result.redactions)


def test_sanitize_unknown_entity_type(engine):
    with pytest.raises(ValueError, match="passport"):
        engine.sanitize(SanitizeRequest(text="ada@example.com", entity_types=["passport"]))


def test_sanitize_can_limit_entity_types(engine):
    text = "ada@example.com and +1 415 555 0134"
    result = engine.sanitize(SanitizeRequest(text=text, entity_types=["email"]))
    assert result.text == "[EMAIL_1] and +1 415 555 0134"
    assert [item.entity_type for item in result.redactions] == ["email"]


def test_spaced_iban_is_redacted(engine):
    result = engine.sanitize(
        SanitizeRequest(text="IBAN DE89 3704 0044 0532 0130 00 thanks", reversible=False)
    )
    assert "[IBAN_1]" in result.text
    assert "3704" not in result.text
