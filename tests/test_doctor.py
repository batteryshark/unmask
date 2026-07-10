"""`unmask tools doctor` readiness check + .env loading.

Doctor answers "can this install actually run everything?" — RE providers, their external
tool prerequisites (with install hints), and whether a review model is configured. The
report is JSON-able so setup.sh can consume it; these tests pin the shape and the render.
"""

from __future__ import annotations

import os

import pytest

from unmask import doctor

_REVIEW_ENV = ("UNMASK_REVIEW_PROVIDER", "UNMASK_REVIEW_MODEL", "UNMASK_REVIEW_BASE_URL",
               "UNMASK_REVIEW_API_KEY", "UNMASK_REVIEW_KIND")


def _clear_review_env(monkeypatch):
    for k in _REVIEW_ENV:
        monkeypatch.delenv(k, raising=False)


# --- review model status ---------------------------------------------------

def test_review_model_status_unconfigured(monkeypatch):
    _clear_review_env(monkeypatch)
    st = doctor._review_model_status()
    assert st["configured"] is False and st.get("reason")


def test_review_model_status_configured_via_env(monkeypatch):
    _clear_review_env(monkeypatch)
    monkeypatch.setenv("UNMASK_REVIEW_PROVIDER", "lmstudio")
    monkeypatch.setenv("UNMASK_REVIEW_MODEL", "qwen-coder")
    st = doctor._review_model_status()
    assert st["configured"] is True
    assert st["provider"] == "lmstudio" and st["model"] == "qwen-coder"
    assert st["baseUrl"].startswith("http")   # the preset filled base_url in
    assert st["hasApiKey"] is False           # a boolean, never the key itself → no leak


# --- readiness report shape ------------------------------------------------

def test_readiness_report_shape(monkeypatch):
    _clear_review_env(monkeypatch)
    rep = doctor.readiness_report()
    assert "reProvidersInstalled" in rep
    assert isinstance(rep.get("externalTools"), list)
    assert isinstance(rep.get("reviewModel"), dict)
    for t in rep["externalTools"]:
        assert {"tool", "present", "neededBy"} <= set(t)


def test_render_readiness_has_all_sections(monkeypatch):
    _clear_review_env(monkeypatch)
    out = doctor.render_readiness(doctor.readiness_report())
    assert "RE providers:" in out
    assert "Review model:" in out


def test_render_readiness_flags_missing_tool_with_hint():
    rep = {
        "reProvidersInstalled": True,
        "providers": [{"id": "x", "capabilities": ["c"], "error": None}],
        "externalTools": [{"tool": "jadx", "present": False,
                           "hint": "brew install jadx", "neededBy": ["jvm-decompile"]}],
        "reviewModel": {"configured": False, "reason": "none"},
        "hint": None,
    }
    out = doctor.render_readiness(rep)
    assert "jadx" in out and "missing" in out and "brew install jadx" in out
    assert "not configured" in out


# --- external-tool prereqs surface (from the RE provider) ------------------

def test_provider_exposes_prerequisites_status():
    pytest.importorskip("unmask_re")
    from unmask_re.provider import provider
    ps = provider.prerequisites_status()
    assert isinstance(ps, list) and ps
    assert "python3" in {t["tool"] for t in ps}   # every skill needs python3
    for t in ps:
        assert {"tool", "present", "hint", "neededBy"} <= set(t)


# --- .env loading (the CLI wires this at startup) --------------------------

def test_load_dotenv_reads_file(tmp_path, monkeypatch):
    from unmask import cli
    monkeypatch.delenv("UNMASK_REVIEW_MODEL", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("UNMASK_REVIEW_MODEL=from-dotenv\n")
    try:
        cli._load_dotenv()
        assert os.environ.get("UNMASK_REVIEW_MODEL") == "from-dotenv"
    finally:
        os.environ.pop("UNMASK_REVIEW_MODEL", None)   # load_dotenv sets os.environ directly


def test_load_dotenv_missing_file_is_noop(tmp_path, monkeypatch):
    from unmask import cli
    monkeypatch.chdir(tmp_path)   # no .env here
    cli._load_dotenv()            # must not raise
