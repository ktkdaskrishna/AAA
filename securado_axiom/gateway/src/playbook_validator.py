from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path


class PlaybookValidationError(ValueError):
    pass


REQUIRED_FIELDS = {
    "technique_id",
    "name",
    "tactic",
    "risk_level",
    "tools",
    "command_template",
    "detection_artifacts",
    "compliance_mapping",
    "requires_approval",
}
VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "DESTRUCTIVE"}


def _canonical_entries(entries: list[dict]) -> str:
    return json.dumps(entries, sort_keys=True, separators=(",", ":"))


def compute_signature(entries: list[dict], signing_secret: str) -> str:
    payload = _canonical_entries(entries)
    return hmac.new(signing_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def validate_schema(entries: list[dict]) -> None:
    for idx, entry in enumerate(entries):
        missing = REQUIRED_FIELDS - set(entry.keys())
        if missing:
            raise PlaybookValidationError(f"ENTRY_{idx}_MISSING_FIELDS:{sorted(missing)}")
        if entry.get("risk_level") not in VALID_RISK_LEVELS:
            raise PlaybookValidationError(f"ENTRY_{idx}_INVALID_RISK")
        if not isinstance(entry.get("tools"), list) or not entry["tools"]:
            raise PlaybookValidationError(f"ENTRY_{idx}_INVALID_TOOLS")


def validate_signed_bundle(entries_path: Path, signature_path: Path, signing_secret: str) -> list[dict]:
    entries = json.loads(entries_path.read_text(encoding="utf-8"))
    validate_schema(entries)
    actual = compute_signature(entries, signing_secret)
    expected = signature_path.read_text(encoding="utf-8").strip()
    if not hmac.compare_digest(actual, expected):
        raise PlaybookValidationError("PLAYBOOK_SIGNATURE_INVALID")
    return entries
