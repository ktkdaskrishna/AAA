from __future__ import annotations

import time
from pathlib import Path

import pytest

from securado_axiom.gateway.src.auth import build_hmac_token
from securado_axiom.gateway.src.server import GatewayService


def _sad_payload() -> dict:
    now = int(time.time())
    return {
        "engagement_id": "ENG-TEST-1",
        "allowed_cidrs": ["10.0.0.0/24"],
        "excluded_ips": ["10.0.0.10"],
        "window_start": now - 60,
        "window_end": now + 3600,
        "permitted_tactics": ["Reconnaissance", "Execution"],
        "session_secret": "testsecret",
        "signature": "SIGNED_BY_AUTHORIZED_KEY",
    }


def _service(tmp_path: Path) -> GatewayService:
    return GatewayService(audit_path=tmp_path / "audit.log")


def test_load_sad_success(tmp_path: Path) -> None:
    svc = _service(tmp_path)
    response = svc.load_sad(_sad_payload())
    assert response["status"] == "loaded"


def test_scope_enforcement_blocks_out_of_scope(tmp_path: Path) -> None:
    svc = _service(tmp_path)
    sad = _sad_payload()
    svc.load_sad(sad)
    msg = "T1046:192.168.1.10:nmap -sV 192.168.1.10"
    token = build_hmac_token(sad["session_secret"], msg)
    with pytest.raises(ValueError, match="OUT_OF_SCOPE"):
        svc.execute_tool(
            {
                "token": token,
                "technique_id": "T1046",
                "tactic": "Reconnaissance",
                "targets": ["192.168.1.10"],
                "tool": "nmap",
                "command": "nmap -sV 192.168.1.10",
            }
        )


def test_high_risk_requires_approval(tmp_path: Path) -> None:
    svc = _service(tmp_path)
    sad = _sad_payload()
    svc.load_sad(sad)
    msg = "T1059.001:10.0.0.12:powershell -EncodedCommand AAA"
    token = build_hmac_token(sad["session_secret"], msg)
    with pytest.raises(PermissionError, match="APPROVAL_REQUIRED"):
        svc.execute_tool(
            {
                "token": token,
                "technique_id": "T1059.001",
                "tactic": "Execution",
                "targets": ["10.0.0.12"],
                "tool": "msfconsole",
                "command": "powershell -EncodedCommand AAA",
            }
        )


def test_kill_switch_blocks_execution(tmp_path: Path) -> None:
    svc = _service(tmp_path)
    sad = _sad_payload()
    svc.load_sad(sad)
    svc.activate_kill_switch()
    msg = "T1046:10.0.0.12:nmap -sV 10.0.0.12"
    token = build_hmac_token(sad["session_secret"], msg)
    with pytest.raises(PermissionError, match="Kill switch active"):
        svc.execute_tool(
            {
                "token": token,
                "technique_id": "T1046",
                "tactic": "Reconnaissance",
                "targets": ["10.0.0.12"],
                "tool": "nmap",
                "command": "nmap -sV 10.0.0.12",
            }
        )
