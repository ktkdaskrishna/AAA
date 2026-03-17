# Securado Axiom Production Release Plan

This plan converts the current gateway baseline into a full production release via prioritized, testable increments.

## Release Phases

## P0 — Production Safety & Operability (Must-have before GA)

1. **Persistent engagement/session state**
   - Replace process-only runtime state with durable storage.
   - Acceptance: service restart preserves engagement SAD metadata and chain counters.
2. **Secrets hardening**
   - Support secret injection from files (`*_FILE`) and fail fast on insecure defaults in prod mode.
   - Acceptance: startup fails in strict mode when required secrets are missing/weak.
3. **Operational endpoints**
   - Add readiness endpoint and minimal Prometheus-style metrics endpoint.
   - Acceptance: `/ready` reflects dependency readiness and `/metrics` exposes counters.
4. **Structured error model**
   - Return stable machine-readable error codes.
   - Acceptance: API responses include `error_code` for every non-2xx.
5. **Audit retention and rotation strategy**
   - Define and implement log lifecycle controls.

## P1 — Security & Platform Hardening

1. Reverse proxy/TLS reference deployment (Nginx/Caddy) with hardened headers.
2. mTLS between control-plane components.
3. External secret manager adapter (Vault/KMS).
4. Centralized observability (metrics + traces + alert rules).
5. Expand playbook/tool schema validation and signed playbook bundle checks.

## P2 — Scale, Resilience, and Enterprise Ops

1. HA deployment model (active/standby or active/active).
2. Distributed rate limiting + queue-backed execution control.
3. Multi-tenant authN/authZ and RBAC.
4. Incident response automation and compliance evidence packs.
5. SLOs, load tests, chaos tests, and DR runbooks.

---

## Initial Implementation Order (Started in this PR)

Implemented now (in order):
1. P0.1 persistent engagement/session state store.
2. P0.2 secrets file support and strict-production config checks.
3. P0.3 readiness + metrics endpoints.
4. P1.1 reverse proxy reference deployment with hardened headers (nginx).
5. P1.5 signed playbook bundle verification + schema checks.
6. P2.5 initial SLO/load-test utility script baseline.
