from __future__ import annotations

import json
from pathlib import Path


PLAYBOOK_PATH = Path(__file__).resolve().parents[2] / "playbooks" / "entries.json"


def load_playbooks() -> dict[str, dict]:
    with PLAYBOOK_PATH.open("r", encoding="utf-8") as f:
        entries = json.load(f)
    return {entry["technique_id"]: entry for entry in entries}
