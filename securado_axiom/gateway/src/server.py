from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from .audit_logger import AuditLogger
from .auth import verify_hmac
from .kill_switch import KillSwitch
from .models import SAD, ToolCall
from .rate_limiter import SlidingWindowRateLimiter
from .risk_classifier import classify_risk
from .sad_validator import SADValidationError, validate_sad
from .scope_enforcer import enforce_scope
from .settings import Settings, load_settings


class GatewayService:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or load_settings()
        self.sad: SAD | None = None
        self.kill_switch = KillSwitch()
        self.audit = AuditLogger(self.settings.audit_log_path)
        self.chain_count = 0
        self.rate_limiter = SlidingWindowRateLimiter(self.settings.rate_limit_per_minute)

    def health(self) -> dict:
        return {
            "status": "ok",
            "kill_switch": self.kill_switch.active,
            "engagement_loaded": bool(self.sad),
            "chain_count": self.chain_count,
            "max_chain_length": self.settings.max_chain_length,
        }

    def load_sad(self, sad_payload: dict) -> dict:
        sad = SAD(**sad_payload)
        now = int(time.time())
        validate_sad(sad, now, self.settings.sad_signing_secret)
        self.sad = sad
        self.chain_count = 0
        self.audit.append({"event_type": "sad_loaded", "engagement_id": sad.engagement_id, "timestamp": now})
        return {"status": "loaded", "engagement_id": sad.engagement_id}

    def activate_kill_switch(self, actor: str = "system") -> dict:
        self.kill_switch.activate()
        engagement_id = self.sad.engagement_id if self.sad else "NONE"
        self.audit.append(
            {
                "event_type": "kill_switch_activated",
                "engagement_id": engagement_id,
                "timestamp": int(time.time()),
                "details": {"actor": actor},
            }
        )
        return {"status": "kill_switch_active"}

    def reset_kill_switch(self, actor: str = "system") -> dict:
        self.kill_switch.deactivate()
        engagement_id = self.sad.engagement_id if self.sad else "NONE"
        self.audit.append(
            {
                "event_type": "kill_switch_reset",
                "engagement_id": engagement_id,
                "timestamp": int(time.time()),
                "details": {"actor": actor},
            }
        )
        return {"status": "kill_switch_inactive"}

    def execute_tool(self, call_payload: dict) -> dict:
        if self.kill_switch.active:
            raise PermissionError("Kill switch active")
        if self.sad is None:
            raise ValueError("SAD not loaded")
        if self.chain_count >= self.settings.max_chain_length:
            raise PermissionError("CHAIN_LIMIT_REACHED")

        call = ToolCall(**call_payload)
        now = int(time.time())

        validate_sad(self.sad, now, self.settings.sad_signing_secret)
        enforce_scope(call.targets, self.sad.allowed_cidrs, self.sad.excluded_ips)
        if call.tactic not in self.sad.permitted_tactics:
            raise PermissionError("TACTIC_NOT_PERMITTED")

        message = f"{call.technique_id}:{','.join(call.targets)}:{call.command}"
        if not verify_hmac(call.token, self.sad.session_secret, message):
            raise PermissionError("AUTH_FAILED")

        self.rate_limiter.check(call.tool)

        risk_level = classify_risk(call.technique_id)
        if risk_level in {"HIGH", "DESTRUCTIVE"} and not call.approved_by:
            raise PermissionError("APPROVAL_REQUIRED")

        self.chain_count += 1
        result = {
            "status": "executed",
            "technique_id": call.technique_id,
            "risk_level": risk_level,
            "tool": call.tool,
            "chain_count": self.chain_count,
        }
        self.audit.append(
            {
                "event_type": "tool_executed",
                "engagement_id": self.sad.engagement_id,
                "timestamp": now,
                "details": result,
            }
        )
        return result


class GatewayHTTPAPI:
    def __init__(self, service: GatewayService | None = None):
        self.service = service or GatewayService()

    def handle(self, method: str, path: str, body: dict | None, headers: dict[str, str] | None = None) -> tuple[int, dict]:
        headers = headers or {}
        try:
            if method == "GET" and path == "/health":
                return 200, self.service.health()
            if method == "POST" and path == "/engagement/load-sad":
                return 200, self.service.load_sad(body or {})
            if method == "POST" and path == "/tools/execute":
                return 200, self.service.execute_tool(body or {})
            if method == "POST" and path in {"/control/kill", "/control/reset-kill"}:
                if headers.get("x-api-key") != self.service.settings.admin_api_key:
                    return 401, {"error": "UNAUTHORIZED"}
                if path.endswith("kill") and not path.endswith("reset-kill"):
                    return 200, self.service.activate_kill_switch(actor="api_admin")
                return 200, self.service.reset_kill_switch(actor="api_admin")
            return 404, {"error": "NOT_FOUND"}
        except (ValueError, PermissionError, SADValidationError) as exc:
            return 400, {"error": str(exc)}


def _demo() -> None:
    svc = GatewayService()
    print("Securado Axiom Gateway service initialized")
    print(json.dumps(svc.health(), indent=2))
    print(json.dumps(asdict(svc.settings), indent=2, default=str))


if __name__ == "__main__":
    _demo()
