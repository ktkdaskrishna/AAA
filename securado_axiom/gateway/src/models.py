from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "DESTRUCTIVE"]


@dataclass
class SAD:
    engagement_id: str
    allowed_cidrs: list[str]
    excluded_ips: list[str] = field(default_factory=list)
    window_start: int = 0
    window_end: int = 0
    permitted_tactics: list[str] = field(default_factory=list)
    session_secret: str = ""
    signature: str = ""


@dataclass
class ToolCall:
    token: str
    technique_id: str
    tactic: str
    targets: list[str]
    tool: str
    command: str
    requires_approval: bool = False
    approved_by: str | None = None


@dataclass
class ValidationResult:
    authorized: bool
    risk_level: RiskLevel


@dataclass
class AuditEvent:
    event_type: str
    engagement_id: str
    details: dict
    timestamp: int
