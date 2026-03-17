from __future__ import annotations

import hashlib
import json
from pathlib import Path


class AuditLogger:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def _last_hash(self) -> str:
        lines = self.path.read_text(encoding="utf-8").strip().splitlines()
        if not lines:
            return "GENESIS"
        return json.loads(lines[-1])["hash"]

    def append(self, event: dict) -> None:
        previous_hash = self._last_hash()
        payload = json.dumps(event, sort_keys=True)
        digest = hashlib.sha256(f"{previous_hash}:{payload}".encode()).hexdigest()
        row = {"previous_hash": previous_hash, "hash": digest, "event": event}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")

    def verify_integrity(self) -> bool:
        previous_hash = "GENESIS"
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("previous_hash") != previous_hash:
                return False
            payload = json.dumps(row["event"], sort_keys=True)
            expected = hashlib.sha256(f"{previous_hash}:{payload}".encode()).hexdigest()
            if row.get("hash") != expected:
                return False
            previous_hash = row["hash"]
        return True
