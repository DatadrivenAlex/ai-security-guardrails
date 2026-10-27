from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from guardrails.api.app import create_app
from guardrails.config import Settings
from guardrails.core.engine import RulesEngine
from guardrails.core.policy import Policy, load_policy

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "default.yaml"


@pytest.fixture
def policy() -> Policy:
    return load_policy(POLICY_PATH)


@pytest.fixture
def engine(policy: Policy) -> RulesEngine:
    return RulesEngine(policy)


@pytest.fixture
def client(policy: Policy) -> TestClient:
    settings = Settings(log_prompts=False, log_json=True, policy_path=POLICY_PATH)
    application = create_app(policy=policy, settings=settings)
    return TestClient(application)
