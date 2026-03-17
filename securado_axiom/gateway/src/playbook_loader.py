from __future__ import annotations

from pathlib import Path

from .playbook_validator import validate_signed_bundle
from .settings import load_settings


PLAYBOOK_PATH = Path(__file__).resolve().parents[2] / "playbooks" / "entries.json"
PLAYBOOK_SIG_PATH = Path(__file__).resolve().parents[2] / "playbooks" / "entries.sig"

_CACHE: dict[str, dict] | None = None


def load_playbooks() -> dict[str, dict]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE

    settings = load_settings()
    entries = validate_signed_bundle(PLAYBOOK_PATH, PLAYBOOK_SIG_PATH, settings.playbook_signing_secret)
    _CACHE = {entry["technique_id"]: entry for entry in entries}
    return _CACHE


def clear_playbook_cache() -> None:
    global _CACHE
    _CACHE = None
