from __future__ import annotations

import json
import time
from pathlib import Path

from .audit_logger import AuditLogger
from .auth import verify_hmac
from .kill_switch import KillSwitch
from .models import SAD, ToolCall
from .risk_classifier import UnknownTechniqueError, classify_risk
from .sad_validator import SADValidationError, validate_sad
from .scope_enforcer import ScopeError, enforce_scope


class GatewayService:
    def __init__(self, audit_path: Path | None = None):
        self.sad: SAD | None = None
        self.kill_switch = KillSwitch()
        self.audit = AuditLogger(audit_path or Path("securado_axiom/audit/audit.log"))

    def health(self) -> dict:
        return {"status": "ok", "kill_switch": self.kill_switch.active}

    def load_sad(self, sad_payload: dict) -> dict:
        sad = SAD(**sad_payload)
        now = int(time.time())
        validate_sad(sad, now)
        self.sad = sad
        self.audit.append({"event_type": "sad_loaded", "engagement_id": sad.engagement_id, "timestamp": now})
        return {"status": "loaded", "engagement_id": sad.engagement_id}

    def activate_kill_switch(self) -> dict:
        self.kill_switch.activate()
        engagement_id = self.sad.engagement_id if self.sad else "NONE"
        self.audit.append({"event_type": "kill_switch_activated", "engagement_id": engagement_id, "timestamp": int(time.time())})
        return {"status": "kill_switch_active"}

    def reset_kill_switch(self) -> dict:
        self.kill_switch.deactivate()
        return {"status": "kill_switch_inactive"}

    def execute_tool(self, call_payload: dict) -> dict:
        if self.kill_switch.active:
            raise PermissionError("Kill switch active")
        if self.sad is None:
            raise ValueError("SAD not loaded")

        call = ToolCall(**call_payload)
        now = int(time.time())

        validate_sad(self.sad, now)
        enforce_scope(call.targets, self.sad.allowed_cidrs, self.sad.excluded_ips)

        message = f"{call.technique_id}:{','.join(call.targets)}:{call.command}"
        if not verify_hmac(call.token, self.sad.session_secret, message):
            raise PermissionError("AUTH_FAILED")

        risk_level = classify_risk(call.technique_id)
        if risk_level in {"HIGH", "DESTRUCTIVE"} and not call.approved_by:
            raise PermissionError("APPROVAL_REQUIRED")

        result = {"status": "executed", "technique_id": call.technique_id, "risk_level": risk_level, "tool": call.tool}
        self.audit.append({"event_type": "tool_executed", "engagement_id": self.sad.engagement_id, "timestamp": now, "details": result})
        return result


def _demo() -> None:
    svc = GatewayService()
    print("Securado Axiom Gateway service initialized")
    print(json.dumps(svc.health(), indent=2))


if __name__ == "__main__":
    try:
        _demo()
    except (SADValidationError, ScopeError, UnknownTechniqueError, PermissionError, ValueError) as exc:
        print(f"Gateway error: {exc}")
