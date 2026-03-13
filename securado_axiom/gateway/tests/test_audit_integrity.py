from __future__ import annotations

from pathlib import Path

from securado_axiom.gateway.src.audit_logger import AuditLogger


def test_audit_integrity_detects_tamper(tmp_path: Path) -> None:
    p = tmp_path / "audit.log"
    logger = AuditLogger(p)
    logger.append({"event_type": "one"})
    logger.append({"event_type": "two"})
    assert logger.verify_integrity() is True

    lines = p.read_text(encoding="utf-8").splitlines()
    lines[-1] = lines[-1].replace("two", "tampered")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert logger.verify_integrity() is False
