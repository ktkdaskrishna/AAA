from __future__ import annotations

from pathlib import Path

from .log_parser import parse_audit_log
from .score_engine import detection_fidelity_score


def build_assessment_report(audit_path: Path) -> dict:
    events = parse_audit_log(audit_path)
    technique_results = []
    for event in events:
        if event.get("event_type") != "tool_executed":
            continue
        details = event.get("details", {})
        technique_results.append(
            {
                "technique_id": details.get("technique_id"),
                "tool": details.get("tool"),
                "result": "Detected" if details.get("risk_level") in {"HIGH", "DESTRUCTIVE"} else "Blocked",
            }
        )

    return {
        "executive_summary": "Securado Axiom engagement summary",
        "technique_results": technique_results,
        "detection_fidelity_score": detection_fidelity_score(technique_results),
    }
