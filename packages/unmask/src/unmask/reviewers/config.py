"""Review model configuration — any OpenAI-compatible endpoint.

The reviewer talks to whatever endpoint you point it at: a local server
(LM Studio, Ollama, llama.cpp), MiniMax, z.ai/GLM, OpenAI, or an Anthropic-
compatible gateway. They are all OpenAI chat-completions compatible, so one code
path (base_url + api_key + model) covers them.

Resolution (env-first, presets fill the base_url):

    UNMASK_REVIEW_PROVIDER   preset name (lmstudio|minimax|zai|openai) or "custom"
    UNMASK_REVIEW_MODEL      model id (required)
    UNMASK_REVIEW_BASE_URL   overrides the preset base_url
    UNMASK_REVIEW_API_KEY    overrides the preset's api-key env var

Nothing here depends on pi or any external config; it is all env-driven so the
core stays self-contained. pydantic-ai is an optional dep (`unmask[review]`).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class ReviewConfigError(RuntimeError):
    """Raised when the review model is requested but not configured."""


# base_url + which env var holds the api key. Override any of it via env.
_PRESETS = {
    "lmstudio": {"base_url": "http://localhost:1234/v1", "api_key_env": "UNMASK_REVIEW_API_KEY", "local": True},
    "minimax": {"base_url": "https://api.minimax.chat/v1", "api_key_env": "MINIMAX_API_KEY", "local": False},
    "zai": {"base_url": "https://api.z.ai/api/paas/v4", "api_key_env": "ZAI_API_KEY", "local": False},
    "openai": {"base_url": "https://api.openai.com/v1", "api_key_env": "OPENAI_API_KEY", "local": False},
}


@dataclass
class ReviewModelConfig:
    model: str
    base_url: str
    api_key: str | None
    provider: str

    @classmethod
    def from_spec(cls, spec: str | None, **kw) -> "ReviewModelConfig":
        """Resolve a `[provider:]model_id` spec (e.g. 'lmstudio:qwen2.5' or 'gpt-4o'),
        falling back to env for base_url/api_key. `spec=None` is pure env resolution —
        used by per-role model routing so a role can override just the model."""
        if not spec:
            return cls.from_env(**kw)
        provider, sep, model = spec.partition(":")
        if sep and model:
            return cls.from_env(provider=provider, model=model, **kw)
        return cls.from_env(model=provider, **kw)  # bare model id

    @classmethod
    def from_env(cls, *, model=None, base_url=None, api_key=None, provider=None) -> "ReviewModelConfig":
        provider = provider or os.environ.get("UNMASK_REVIEW_PROVIDER", "custom")
        model = model or os.environ.get("UNMASK_REVIEW_MODEL")
        base_url = base_url or os.environ.get("UNMASK_REVIEW_BASE_URL")
        api_key = api_key or os.environ.get("UNMASK_REVIEW_API_KEY")

        preset = _PRESETS.get(provider)
        if preset:
            base_url = base_url or preset["base_url"]
            if not api_key:
                api_key = os.environ.get(preset["api_key_env"] or "")

        if not model:
            raise ReviewConfigError(
                "no review model configured — set UNMASK_REVIEW_MODEL (and a base_url via "
                "UNMASK_REVIEW_BASE_URL or UNMASK_REVIEW_PROVIDER=lmstudio|minimax|zai|openai)."
            )
        if not base_url:
            raise ReviewConfigError(
                f"no base_url for review model {model!r} — set UNMASK_REVIEW_BASE_URL or a known "
                "UNMASK_REVIEW_PROVIDER."
            )
        return cls(model=model, base_url=base_url, api_key=api_key, provider=provider)

    def build_model(self):
        """Construct a pydantic-ai OpenAI-compatible chat model."""
        try:
            from pydantic_ai.models.openai import OpenAIChatModel
            from pydantic_ai.providers.openai import OpenAIProvider
        except ImportError as e:  # pragma: no cover
            raise ReviewConfigError("agentic review needs `pip install unmask[review]`") from e
        provider = OpenAIProvider(base_url=self.base_url, api_key=self.api_key or "not-needed")
        return OpenAIChatModel(self.model, provider=provider)
