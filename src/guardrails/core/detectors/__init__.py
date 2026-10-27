"""Built-in deterministic detectors."""

from guardrails.core.detectors.base import Detector
from guardrails.core.detectors.denylist import DenylistDetector
from guardrails.core.detectors.echo import SystemPromptEchoDetector
from guardrails.core.detectors.encoding import EncodedPayloadDetector
from guardrails.core.detectors.injection import (
    InstructionOverrideDetector,
    JailbreakDetector,
    RoleplayEscapeDetector,
)
from guardrails.core.detectors.pii import PiiDetector
from guardrails.core.detectors.secrets import SecretLeakDetector
from guardrails.core.policy import Policy


def build_detectors(policy: Policy) -> list[Detector]:
    return [
        InstructionOverrideDetector(),
        JailbreakDetector(),
        RoleplayEscapeDetector(),
        EncodedPayloadDetector(),
        PiiDetector(),
        SecretLeakDetector(),
        SystemPromptEchoDetector(),
        DenylistDetector(policy.denylist),
    ]
