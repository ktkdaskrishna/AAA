# Securado Axiom Admin Guide

## 1) Purpose

This guide helps administrators operate the current Securado Axiom MVP safely and consistently.

---

## 2) Admin Responsibilities

- Maintain legal/authorized engagement boundaries.
- Ensure valid SAD documents are used for all runs.
- Manage session secrets and signing trust chain.
- Enforce approval workflow for HIGH/DESTRUCTIVE techniques.
- Monitor and preserve immutable audit logs.
- Trigger and validate kill switch when needed.

---

## 3) Operational Workflow

1. **Prepare engagement**
   - Confirm scope, excludes, and time window.
   - Generate/load SAD payload.
2. **Initialize service**
   - Start gateway service runtime.
   - Verify health output.
3. **Authorize execution**
   - Provide valid HMAC token per tool request.
   - Confirm target scope is in SAD allowlist.
4. **Approval gate handling**
   - For HIGH/DESTRUCTIVE actions, require `approved_by` metadata.
5. **Incident handling**
   - Activate kill switch immediately on abnormal behavior.
6. **Post-engagement**
   - Preserve audit log, generate report, archive artifacts.

---

## 4) SAD Administration

Required SAD fields:
- `engagement_id`
- `allowed_cidrs`
- `excluded_ips`
- `window_start`, `window_end`
- `permitted_tactics`
- `session_secret`
- `signature`

Admin checks:
- Signature is valid for trusted signer policy.
- Engagement window is current.
- Exclusion list includes protected assets.

---

## 5) Token / Auth Administration

Admin control endpoints (`/control/kill`, `/control/reset-kill`) require the `x-api-key` header matching `AXIOM_ADMIN_API_KEY`.


- HMAC token message format must match runtime expectation:
  - `<technique_id>:<comma_separated_targets>:<command>`
- Rotate session secrets per engagement.
- Do not reuse secrets across clients.
- Store secrets outside repo and process history.

---

## 6) Kill Switch Procedure

When to use:
- Out-of-scope behavior suspected.
- Unexpected service or target instability.
- Missing approval evidence on high-risk path.

Procedure:
1. Activate kill switch.
2. Confirm execution requests are blocked.
3. Preserve audit log state.
4. Notify stakeholders and begin incident response.

---

## 7) Audit Log Administration

Audit log properties:
- Append-only JSON-lines.
- Each event links to previous hash.

Admin tasks:
- Restrict write access to service account.
- Keep read access least-privilege.
- Periodically verify chain integrity.
- Archive and retain per policy.

---

## 8) Routine Admin Checklist

Daily / per engagement:
- [ ] Verify service startup and health.
- [ ] Validate SAD and active window.
- [ ] Confirm kill switch is reachable.
- [ ] Confirm approval gate for HIGH risk.
- [ ] Confirm audit log writes and integrity.

Weekly:
- [ ] Review retained logs and storage health.
- [ ] Review signer trust config.
- [ ] Review dependency and security updates.

---

## 9) Troubleshooting

### SAD rejected
- Check signature value and time window.
- Verify all required SAD fields are present.

### AUTH_FAILED
- Recompute HMAC with exact expected message format.
- Confirm correct session secret.

### OUT_OF_SCOPE / EXCLUDED_TARGET
- Validate target against `allowed_cidrs` and `excluded_ips`.

### APPROVAL_REQUIRED
- Provide `approved_by` metadata for HIGH/DESTRUCTIVE techniques.

### Kill switch blocks all runs
- Confirm intended state and reset only after incident triage.
