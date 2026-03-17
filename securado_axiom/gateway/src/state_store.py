from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .models import SAD


class StateStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(json.dumps({"sad": None, "chain_count": 0}), encoding="utf-8")

    def save(self, sad: SAD | None, chain_count: int) -> None:
        payload = {"sad": asdict(sad) if sad else None, "chain_count": chain_count}
        self.path.write_text(json.dumps(payload), encoding="utf-8")

    def load(self) -> tuple[SAD | None, int]:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        sad = SAD(**data["sad"]) if data.get("sad") else None
        return sad, int(data.get("chain_count", 0))
