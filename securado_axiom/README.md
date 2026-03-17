# Securado Axiom

Securado Axiom is a safety-first security control validation platform inspired by the WAT PRD.

## Production-Ready Baseline Included
- HTTP gateway API (`WSGI`) with operational endpoints
- Scope Authorization Document (SAD) validation with HMAC signature verification
- Per-call HMAC authentication
- Scope and engagement-window enforcement
- Risk classification + human approval gate for high-risk techniques
- Chain-length control and in-memory rate limiter
- Append-only hash-chained audit log + integrity verification
- Global kill switch with admin API key guard
- Playbook loader and sample ATT&CK entries
- Basic report generation from audit logs
- Dockerfile + compose baseline with optional hardened reverse proxy

## One-command Docker Install
```bash
bash docker/scripts/install.sh
```

## Quickstart
```bash
python -m pip install -e .
python -m securado_axiom.gateway.src.app
```

### API endpoints
- `GET /health`
- `POST /engagement/load-sad`
- `POST /tools/execute`
- `POST /control/kill` (requires `x-api-key`)
- `POST /control/reset-kill` (requires `x-api-key`)
- `GET /ready`
- `GET /metrics`

Run tests:
```bash
pytest -q
```

## Additional Documentation
- Deployment guide: `securado_axiom/docs/DEPLOYMENT_GUIDE.md`
- Admin guide: `securado_axiom/docs/ADMIN_GUIDE.md`

- Production release plan: `securado_axiom/docs/PRODUCTION_RELEASE_PLAN.md`

- Load test utility: `python -m securado_axiom.scripts.load_test`
