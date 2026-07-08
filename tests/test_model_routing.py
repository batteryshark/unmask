"""Per-role model routing: cheap for high-volume steps, strong for high-stakes ones.

An injected model overrides every role; otherwise config.models[role] -> config.model ->
UNMASK_REVIEW_* env. Endpoints/keys stay env/harness.
"""

from __future__ import annotations

import pytest

from unmask.config import MCDConfig


def test_from_spec_parses_provider_and_model():
    from unmask.reviewers.config import ReviewModelConfig
    c = ReviewModelConfig.from_spec("lmstudio:qwen2.5-27b")
    assert c.provider == "lmstudio" and c.model == "qwen2.5-27b" and "1234" in c.base_url


def test_from_spec_bare_model_uses_env(monkeypatch):
    monkeypatch.setenv("UNMASK_REVIEW_BASE_URL", "http://host/v1")
    from unmask.reviewers.config import ReviewModelConfig
    c = ReviewModelConfig.from_spec("some-model")
    assert c.model == "some-model" and c.base_url == "http://host/v1"


def test_parse_models_with_aliases():
    from unmask.cli import _parse_models
    assert _parse_models("leads=lmstudio:m3, verifier=zai:glm, qa=openai:gpt-4o") == {
        "proposer": "lmstudio:m3", "verifier": "zai:glm", "qa": "openai:gpt-4o"}
    assert _parse_models(None) == {} and _parse_models("") == {}


def _deps(**cfg):
    from unmask.graph.runner import MCDGraphDeps
    return MCDGraphDeps(ledger=None, config=MCDConfig(**cfg), paths=None, toolchain=None)


def test_model_for_prefers_role_then_default(monkeypatch):
    captured = []

    class _FakeCfg:
        @staticmethod
        def from_spec(spec):
            captured.append(spec)
            return type("M", (), {"build_model": lambda self: f"model:{spec}"})()

    monkeypatch.setattr("unmask.reviewers.config.ReviewModelConfig", _FakeCfg)
    deps = _deps(model="default", models={"verifier": "strong", "proposer": "cheap"})
    assert deps.model_for("verifier") == "model:strong"   # role-specific wins
    assert deps.model_for("proposer") == "model:cheap"
    assert deps.model_for("reviewer") == "model:default"  # falls back to the default spec


def test_injected_model_overrides_all_roles():
    deps = _deps(model="default", models={"verifier": "strong"})
    deps.review_model = "INJECTED"
    assert deps.model_for("verifier") == "INJECTED"
    assert deps.model_for("proposer") == "INJECTED"
