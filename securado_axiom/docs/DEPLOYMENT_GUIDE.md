# Securado Axiom Deployment Guide

## 1) Production-Ready Baseline in This Repo

This repository now provides a **production-ready baseline** gateway service with:
- HTTP API server (`python -m securado_axiom.gateway.src.app`)
- SAD validation with HMAC signature verification
- Per-call HMAC auth, tactic allowlisting, scope/window enforcement
- Approval gate for HIGH/DESTRUCTIVE techniques
- Chain length guard and in-memory rate limiting
- Kill switch with admin API key protection
- Append-only hash-chained audit log + integrity verification
- Docker build/compose artifacts

## 2) Remaining Enterprise Enhancements (Recommended)

- External datastore for sessions/state.
- External secret manager and key rotation automation.
- Reverse proxy TLS termination + mTLS for internal hops.
- Centralized metrics/tracing/alerting.
- HA deployment topology.

## 3) Prerequisites

- Python 3.10+
- Docker (optional for container deployment)
- Linux/macOS host

## 4) Environment Configuration

Create `.env` from `.env.example` and set secure values:

- `AXIOM_AUDIT_LOG_PATH`
- `AXIOM_STATE_STORE_PATH`
- `AXIOM_SAD_SIGNING_SECRET`
- `AXIOM_MAX_CHAIN_LENGTH`
- `AXIOM_RATE_LIMIT_PER_MINUTE`
- `AXIOM_ADMIN_API_KEY`
- `AXIOM_STRICT_PRODUCTION`

## 5) Local Deployment

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
pytest -q
python -m securado_axiom.gateway.src.app
```

Service listens on `0.0.0.0:8080`.

## 6) API Smoke Test

```bash
curl -s http://localhost:8080/health
```

## 7) Container Deployment

One-command installer:

```bash
bash docker/scripts/install.sh
```

Manual compose:

```bash
docker compose -f docker/docker-compose.yml up --build -d
```

Stop:

```bash
docker compose -f docker/docker-compose.yml down
```

## 8) Deployment Verification Checklist

- [ ] `/health` returns `status=ok`
- [ ] `/ready` returns `status=ready`
- [ ] `/metrics` returns counters
- [ ] Valid SAD can be loaded
- [ ] Out-of-scope target is rejected
- [ ] HIGH-risk technique requires approval
- [ ] Kill switch blocks execution
- [ ] Audit integrity check passes

## 9) Rollback

1. Stop current process/container.
2. Revert to prior tag/commit.
3. Restore previous environment settings.
4. Re-run smoke tests.
