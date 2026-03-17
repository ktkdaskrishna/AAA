from __future__ import annotations

from pathlib import Path

import pytest

from securado_axiom.gateway.src.settings import load_settings


def test_secret_file_loading(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret_file = tmp_path / "admin_key.txt"
    secret_file.write_text("supersecret\n", encoding="utf-8")
    monkeypatch.setenv("AXIOM_ADMIN_API_KEY_FILE", str(secret_file))
    monkeypatch.delenv("AXIOM_ADMIN_API_KEY", raising=False)
    settings = load_settings()
    assert settings.admin_api_key == "supersecret"


def test_strict_production_rejects_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AXIOM_STRICT_PRODUCTION", "true")
    monkeypatch.setenv("AXIOM_ADMIN_API_KEY", "change-me")
    monkeypatch.setenv("AXIOM_SAD_SIGNING_SECRET", "dev-sad-secret")
    monkeypatch.setenv("AXIOM_PLAYBOOK_SIGNING_SECRET", "dev-playbook-secret")
    with pytest.raises(ValueError, match="strict production"):
        load_settings()
