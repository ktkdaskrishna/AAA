from __future__ import annotations

import json
import time
from dataclasses import asdict

from .audit_logger import AuditLogger
from .auth import verify_hmac
from .kill_switch import KillSwitch
from .models import SAD, ToolCall
from .rate_limiter import RateLimitError, SlidingWindowRateLimiter
from .risk_classifier import UnknownTechniqueError, classify_risk
from .playbook_validator import PlaybookValidationError
from .sad_validator import SADValidationError, validate_sad
from .scope_enforcer import ScopeError, enforce_scope
from .settings import Settings, load_settings
from .state_store import StateStore


class GatewayService:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or load_settings()
        self.kill_switch = KillSwitch()
        self.audit = AuditLogger(self.settings.audit_log_path)
        self.rate_limiter = SlidingWindowRateLimiter(self.settings.rate_limit_per_minute)
        self.state_store = StateStore(self.settings.state_store_path)
        self.sad, self.chain_count = self.state_store.load()

    def _persist(self) -> None:
        self.state_store.save(self.sad, self.chain_count)

    def health(self) -> dict:
        return {
            "status": "ok",
            "kill_switch": self.kill_switch.active,
            "engagement_loaded": bool(self.sad),
            "chain_count": self.chain_count,
            "max_chain_length": self.settings.max_chain_length,
        }

    def ready(self) -> dict:
        checks = {
            "audit_log_writable": self.audit.path.parent.exists(),
            "state_store_writable": self.state_store.path.parent.exists(),
            "settings_valid": True,
        }
        return {"status": "ready" if all(checks.values()) else "not_ready", "checks": checks}

    def load_sad(self, sad_payload: dict) -> dict:
        sad = SAD(**sad_payload)
        now = int(time.time())
        validate_sad(sad, now, self.settings.sad_signing_secret)
        self.sad = sad
        self.chain_count = 0
        self._persist()
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
        self._persist()
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
        self.metrics = {
            "requests_total": 0,
            "requests_errors_total": 0,
            "tool_exec_total": 0,
            "kill_switch_activations_total": 0,
        }

    def _map_error(self, exc: Exception) -> tuple[int, str]:
        text = str(exc)
        if isinstance(exc, PermissionError) and text == "AUTH_FAILED":
            return 401, "AUTH_FAILED"
        if isinstance(exc, PermissionError) and text in {"APPROVAL_REQUIRED", "CHAIN_LIMIT_REACHED", "TACTIC_NOT_PERMITTED", "Kill switch active"}:
            return 403, text
        if isinstance(exc, RateLimitError):
            return 429, "RATE_LIMIT_EXCEEDED"
        if isinstance(exc, ScopeError):
            return 403, text
        if isinstance(exc, SADValidationError):
            return 400, "SAD_INVALID"
        if isinstance(exc, UnknownTechniqueError):
            return 400, "UNKNOWN_TECHNIQUE"
        if isinstance(exc, PlaybookValidationError):
            return 500, "PLAYBOOK_BUNDLE_INVALID"
        if isinstance(exc, ValueError):
            return 400, text
        return 500, "INTERNAL_ERROR"

    def handle(self, method: str, path: str, body: dict | None, headers: dict[str, str] | None = None) -> tuple[int, dict]:
        headers = headers or {}
        self.metrics["requests_total"] += 1
        try:
            if method == "GET" and path == "/health":
                return 200, self.service.health()
            if method == "GET" and path == "/ready":
                return 200, self.service.ready()
            if method == "GET" and path == "/metrics":
                return 200, self.metrics.copy()
            if method == "POST" and path == "/engagement/load-sad":
                return 200, self.service.load_sad(body or {})
            if method == "POST" and path == "/tools/execute":
                result = self.service.execute_tool(body or {})
                self.metrics["tool_exec_total"] += 1
                return 200, result
            if method == "POST" and path in {"/control/kill", "/control/reset-kill"}:
                if headers.get("x-api-key") != self.service.settings.admin_api_key:
                    return 401, {"error": "UNAUTHORIZED", "error_code": "UNAUTHORIZED"}
                if path.endswith("kill") and not path.endswith("reset-kill"):
                    self.metrics["kill_switch_activations_total"] += 1
                    return 200, self.service.activate_kill_switch(actor="api_admin")
                return 200, self.service.reset_kill_switch(actor="api_admin")
            return 404, {"error": "NOT_FOUND", "error_code": "NOT_FOUND"}
        except Exception as exc:
            self.metrics["requests_errors_total"] += 1
            status, code = self._map_error(exc)
            return status, {"error": str(exc), "error_code": code}


def _demo() -> None:
    svc = GatewayService()
    print("Securado Axiom Gateway service initialized")
    print(json.dumps(svc.health(), indent=2))
    print(json.dumps(asdict(svc.settings), indent=2, default=str))


if __name__ == "__main__":
    _demo()
