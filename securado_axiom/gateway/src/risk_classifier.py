from __future__ import annotations

from .playbook_loader import load_playbooks


class UnknownTechniqueError(ValueError):
    pass


def classify_risk(technique_id: str) -> str:
    playbooks = load_playbooks()
    if technique_id not in playbooks:
        raise UnknownTechniqueError(f"Unknown technique: {technique_id}")
    return playbooks[technique_id]["risk_level"]
