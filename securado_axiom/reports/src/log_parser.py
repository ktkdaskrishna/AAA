from __future__ import annotations

import json
from pathlib import Path


def parse_audit_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line)["event"] for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
