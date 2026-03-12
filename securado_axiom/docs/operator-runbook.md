# Operator Runbook

1. Load a valid SAD via `/engagement/load-sad`.
2. Validate health via `/health`.
3. Execute approved tool calls through `/tools/execute`.
4. Trigger `/control/kill` if unexpected impact occurs.
5. Build report from `securado_axiom/audit/audit.log`.
