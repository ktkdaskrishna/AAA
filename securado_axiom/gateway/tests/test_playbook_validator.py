from __future__ import annotations

import json
from pathlib import Path

import pytest

from securado_axiom.gateway.src.playbook_validator import (
    PlaybookValidationError,
    compute_signature,
    validate_signed_bundle,
)


def _entries() -> list[dict]:
    return [
        {
            "technique_id": "T1000",
            "name": "Dummy",
            "tactic": "Reconnaissance",
            "risk_level": "LOW",
            "tools": ["nmap"],
            "command_template": "nmap {{target}}",
            "detection_artifacts": {"log_source": "IDS"},
            "compliance_mapping": {"nist_csf": ["DE.CM-1"]},
            "requires_approval": False,
        }
    ]


def test_signed_bundle_validation_success(tmp_path: Path) -> None:
    entries = _entries()
    entries_path = tmp_path / "entries.json"
    sig_path = tmp_path / "entries.sig"
    secret = "abc123"
    entries_path.write_text(json.dumps(entries), encoding="utf-8")
    sig_path.write_text(compute_signature(entries, secret), encoding="utf-8")
    out = validate_signed_bundle(entries_path, sig_path, secret)
    assert out[0]["technique_id"] == "T1000"


def test_signed_bundle_invalid_signature(tmp_path: Path) -> None:
    entries = _entries()
    entries_path = tmp_path / "entries.json"
    sig_path = tmp_path / "entries.sig"
    entries_path.write_text(json.dumps(entries), encoding="utf-8")
    sig_path.write_text("bad", encoding="utf-8")
    with pytest.raises(PlaybookValidationError, match="PLAYBOOK_SIGNATURE_INVALID"):
        validate_signed_bundle(entries_path, sig_path, "abc123")
