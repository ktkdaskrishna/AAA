from __future__ import annotations

import time
from pathlib import Path

import pytest

from securado_axiom.gateway.src.auth import build_hmac_token
from securado_axiom.gateway.src.sad_validator import sign_sad
from securado_axiom.gateway.src.server import GatewayHTTPAPI, GatewayService
from securado_axiom.gateway.src.settings import Settings


TEST_SIGNING_SECRET = "unit-test-signing"


def _sad_payload() -> dict:
    now = int(time.time())
    sad = {
        "engagement_id": "ENG-TEST-1",
        "allowed_cidrs": ["10.0.0.0/24"],
        "excluded_ips": ["10.0.0.10"],
        "window_start": now - 60,
        "window_end": now + 3600,
        "permitted_tactics": ["Reconnaissance", "Execution"],
        "session_secret": "testsecret",
        "signature": "",
    }
    from securado_axiom.gateway.src.models import SAD

    sad_obj = SAD(**sad)
    sad["signature"] = sign_sad(sad_obj, TEST_SIGNING_SECRET)
    return sad


def _service(tmp_path: Path, max_chain_length: int = 10, rate_limit_per_minute: int = 60) -> GatewayService:
    settings = Settings(
        audit_log_path=tmp_path / "audit.log",
        state_store_path=tmp_path / "state.json",
        sad_signing_secret=TEST_SIGNING_SECRET,
        max_chain_length=max_chain_length,
        rate_limit_per_minute=rate_limit_per_minute,
        admin_api_key="admin-key",
        strict_production=False,
    )
    return GatewayService(settings=settings)


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


def test_chain_limit_enforced(tmp_path: Path) -> None:
    svc = _service(tmp_path, max_chain_length=1)
    sad = _sad_payload()
    svc.load_sad(sad)
    msg = "T1046:10.0.0.12:nmap -sV 10.0.0.12"
    token = build_hmac_token(sad["session_secret"], msg)
    payload = {
        "token": token,
        "technique_id": "T1046",
        "tactic": "Reconnaissance",
        "targets": ["10.0.0.12"],
        "tool": "nmap",
        "command": "nmap -sV 10.0.0.12",
    }
    svc.execute_tool(payload)
    with pytest.raises(PermissionError, match="CHAIN_LIMIT_REACHED"):
        svc.execute_tool(payload)


def test_admin_api_key_required_for_kill_switch(tmp_path: Path) -> None:
    api = GatewayHTTPAPI(_service(tmp_path))
    status, body = api.handle("POST", "/control/kill", {}, headers={"x-api-key": "wrong"})
    assert status == 401
    assert body["error_code"] == "UNAUTHORIZED"
    status_ok, payload_ok = api.handle("POST", "/control/kill", {}, headers={"x-api-key": "admin-key"})
    assert status_ok == 200
    assert payload_ok["status"] == "kill_switch_active"


def test_state_persists_across_service_restart(tmp_path: Path) -> None:
    svc = _service(tmp_path)
    sad = _sad_payload()
    svc.load_sad(sad)
    msg = "T1046:10.0.0.12:nmap -sV 10.0.0.12"
    token = build_hmac_token(sad["session_secret"], msg)
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
    svc_restarted = _service(tmp_path)
    health = svc_restarted.health()
    assert health["engagement_loaded"] is True
    assert health["chain_count"] == 1


def test_ready_and_metrics_endpoints(tmp_path: Path) -> None:
    api = GatewayHTTPAPI(_service(tmp_path))
    status_ready, body_ready = api.handle("GET", "/ready", None)
    assert status_ready == 200
    assert body_ready["status"] in {"ready", "not_ready"}

    status_metrics, body_metrics = api.handle("GET", "/metrics", None)
    assert status_metrics == 200
    assert "requests_total" in body_metrics
