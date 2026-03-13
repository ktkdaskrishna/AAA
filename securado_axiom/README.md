# Securado Axiom

Securado Axiom is a safety-first security control validation platform inspired by the WAT PRD.

## MVP Included
- MCP-style security gateway service
- Scope Authorization Document (SAD) validation
- Per-call HMAC authentication
- Scope and engagement-window enforcement
- Risk classification + human approval gate for high-risk techniques
- Append-only hash-chained audit log
- Global kill switch
- Playbook loader and sample ATT&CK entries
- Basic report generation from audit logs

## Quickstart
```bash
python -m pip install -e .
python -m securado_axiom.gateway.src.server
```

Run tests:
```bash
pytest -q
```
