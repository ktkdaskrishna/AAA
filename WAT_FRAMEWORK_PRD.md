# WAT FRAMEWORK
## Weaponized Automation Testing
### Agentic Security Control Validation Platform

> **Document Type:** Product Requirements Document & System Architecture Specification
> **Classification:** CONFIDENTIAL — For Authorized Use Only
> **Version:** 1.0 | March 2026

---

> ⚠️ **WARNING:** This document contains sensitive security architecture details. Distribution is strictly controlled.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Product Requirements](#2-product-requirements)
3. [System Architecture](#3-system-architecture)
4. [Build Plan & Milestones](#4-build-plan--milestones)
5. [Repository Structure](#5-repository-structure)
6. [Compliance & Legal Requirements](#6-compliance--legal-requirements)
7. [Risk Register](#7-risk-register)
8. [Glossary](#8-glossary)

---

## 1. Executive Summary

The WAT (Weaponized Automation Testing) Framework is an agentic, AI-driven security control validation platform designed for authorized red team engagements and compliance assessments on client infrastructure. It combines **Claude Code** as the autonomous decision-making agent, **Kali Linux offensive tools** exposed via the Model Context Protocol (MCP), **MITRE Caldera** for post-exploitation emulation, and a structured **MITRE ATT&CK playbook library** to deliver continuous, repeatable, and fully audited security control assessments.

The platform addresses a critical gap in enterprise security programs: the inability to continuously validate whether defensive controls actually detect and respond to real-world adversary techniques. Manual penetration testing is periodic and expensive; WAT provides automated, structured emulation runs that produce measurable gap reports mapped to industry compliance frameworks.

> ℹ️ **NOTE:** WAT is exclusively designed for use on client infrastructure with explicit written authorization. Every engagement requires a signed Scope Authorization Document loaded at runtime. The platform will refuse to execute without valid authorization.

---

### 1.1 Key Capabilities

- Autonomous attack chain execution driven by Claude Code AI agent
- Kali Linux tool integration via MCP for recon, initial access, and lateral movement
- MITRE Caldera integration for structured post-exploitation emulation
- ATT&CK-mapped playbook library covering 50+ techniques across all tactics
- Mandatory scope enforcement, kill switches, and human approval gates
- Immutable audit logging for every tool call and agent decision
- Automated compliance gap reports mapped to NIST CSF, CIS Controls, and ISO 27001

---

### 1.2 Target Users

| User Role | Primary Use Case | Access Level |
|---|---|---|
| Red Team Lead | Configure and launch full engagement runs | Full Admin |
| Security Analyst | Review findings and validate detections | Read + Approve |
| Compliance Officer | Generate and export gap reports | Reporting Only |
| Client Stakeholder | Receive final assessment reports | Report Delivery |

---

## 2. Product Requirements

### 2.1 Functional Requirements

#### FR-001: Engagement Authorization System

The system **MUST** load and validate a signed Scope Authorization Document (SAD) before initiating any tool call or agent session. The SAD must specify:

- Authorized IP ranges
- Excluded systems
- Engagement window (start/end datetime)
- Permitted technique categories
- A unique engagement ID

The agent **MUST** refuse to operate if the SAD is absent, expired, or cryptographically invalid.

> ⚠️ **CRITICAL:** No tool call — including passive reconnaissance — may execute without a valid, loaded SAD. This is a hard technical gate, not a process control.

---

#### FR-002: Agentic Orchestration Engine

Claude Code **SHALL** serve as the autonomous orchestration layer, responsible for selecting techniques from the playbook library, invoking tools via MCP, interpreting results, and deciding next actions. The agent **MUST** operate within the following constraints:

- All target IPs must be validated against the SAD allowlist before each tool call
- Technique risk level CRITICAL requires explicit human approval before execution
- Agent reasoning steps must be logged with each action decision
- Maximum autonomous chain length: **10 tool calls** before requiring human review

---

#### FR-003: MCP Tool Gateway

All Kali Linux tool invocations **MUST** pass through the WAT MCP Gateway server. The gateway is responsible for scope enforcement, authentication, rate limiting, and audit logging. No tool may be called directly; all calls are proxied through the gateway.

---

#### FR-004: MITRE ATT&CK Playbook Library

The platform **MUST** maintain a structured library of attack playbooks. Each playbook entry **MUST** contain:

- ATT&CK Technique ID and Sub-technique ID (e.g., T1059.001)
- Tactic category (e.g., Execution, Persistence, Lateral Movement)
- Associated tool(s) and command template
- Risk classification: `LOW` / `MEDIUM` / `HIGH` / `DESTRUCTIVE`
- Expected detection artifacts (log source, event ID, rule name)
- Applicable compliance frameworks and control IDs

---

#### FR-005: Caldera Integration

The platform **MUST** integrate with MITRE Caldera via its REST API, allowing the Claude Code agent to instruct Caldera to execute specific adversary emulation plans. The integration must support:

- Agent deployment
- Ability execution
- Fact collection
- Result retrieval

---

#### FR-006: Human Approval Gate

The platform **MUST** pause and await human approval before executing any technique classified as `HIGH` or `DESTRUCTIVE`. Approval requests must be delivered via the VS Code notification panel and must include:

- Technique ID
- Description
- Expected impact
- Target system

Approvals must be logged with approver identity and timestamp.

---

#### FR-007: Kill Switch

A global kill switch **MUST** be accessible from the VS Code interface and from the CLI. Activating the kill switch **MUST**:

- Immediately terminate all active tool calls
- Signal the MCP Gateway to reject further requests
- Write a kill event to the audit log

The kill switch must be testable independently of live engagements.

---

#### FR-008: Reporting Engine

The platform **MUST** produce a structured Assessment Report upon engagement completion. The report must include:

- Executive summary
- Per-technique results (technique ID, tool, target, result: Blocked / Detected / Missed)
- Control gaps
- Detection fidelity score
- Framework-mapped remediation recommendations

---

### 2.2 Non-Functional Requirements

| ID | Category | Requirement | Priority |
|---|---|---|---|
| NFR-001 | Security | All credential captures must be AES-256 encrypted at rest and purged at engagement close | MUST |
| NFR-002 | Security | The MCP Gateway must authenticate every tool call with a per-session HMAC token | MUST |
| NFR-003 | Audit | Audit logs must be append-only, tamper-evident, and retained for 90 days minimum | MUST |
| NFR-004 | Isolation | Each client engagement must run in an isolated container with no shared state | MUST |
| NFR-005 | Performance | MCP Gateway must process tool call authorization in < 100ms | SHOULD |
| NFR-006 | Availability | Platform must support graceful recovery if Claude Code session drops mid-engagement | SHOULD |
| NFR-007 | Compliance | All data handling must comply with applicable data protection laws for client jurisdiction | MUST |
| NFR-008 | Portability | Platform must run on Kali Linux, Ubuntu 22+, and macOS 14+ | SHOULD |

---

## 3. System Architecture

### 3.1 High-Level Architecture

The WAT Framework is organized into five architectural layers. All inter-layer communication is mediated by the MCP Gateway, which acts as the security control plane for the entire system.

```
┌─────────────────────────────────────────────────────────────────┐
│                LAYER 1  —  OPERATOR INTERFACE                   │
│    VS Code + Claude Code  |  CLI  |  Kill Switch  |  Approval   │
└──────────────────────────────┬──────────────────────────────────┘
                               │  ↕  MCP Protocol
┌──────────────────────────────▼──────────────────────────────────┐
│               LAYER 2  —  AI ORCHESTRATION                      │
│   Claude Code Agent  |  Playbook Selector  |  Chain Planner     │
│                       |  Result Interpreter                     │
└──────────────────────────────┬──────────────────────────────────┘
                               │  ↕  Authenticated Tool Calls
┌──────────────────────────────▼──────────────────────────────────┐
│          LAYER 3  —  WAT MCP SECURITY GATEWAY                   │
│  Scope Enforcer | Auth Validator | Risk Classifier              │
│             Audit Logger | Kill Switch                          │
└──────────────────────────────┬──────────────────────────────────┘
                               │  ↕  Controlled Execution
┌──────────────────────────────▼──────────────────────────────────┐
│                LAYER 4  —  EXECUTION LAYER                      │
│  Kali Linux MCP Tools  |  MITRE Caldera REST API                │
│                    ATT&CK Playbook DB                           │
└──────────────────────────────┬──────────────────────────────────┘
                               │  ↓  Structured Results
┌──────────────────────────────▼──────────────────────────────────┐
│                 LAYER 5  —  OUTPUT LAYER                        │
│  Immutable Audit Log  |  Assessment Report                      │
│     Compliance Gap Mapper  |  Export Engine                     │
└─────────────────────────────────────────────────────────────────┘
```

---

### 3.2 Component Breakdown

#### 3.2.1 Operator Interface (VS Code + Claude Code)

VS Code serves as the primary operator interface. The Claude Code extension provides the agent interaction panel. Key interface components:

- **Engagement Configuration Panel** — Load SAD, set parameters, configure target scope
- **Agent Console** — Real-time view of agent reasoning, tool calls, and results
- **Approval Queue** — Human-in-the-loop approval panel for HIGH/DESTRUCTIVE techniques
- **Kill Switch Button** — Prominent, always-accessible emergency stop
- **Report Viewer** — Inline report rendering with export options

---

#### 3.2.2 WAT MCP Gateway Server

The gateway is a Node.js/FastAPI server exposing an MCP-compliant interface to Claude Code. It is the single choke point through which all tool invocations must pass.

| Module | Responsibility | Failure Mode |
|---|---|---|
| SAD Validator | Parse and cryptographically verify the Scope Authorization Document | Hard reject — no tools available |
| Scope Enforcer | Validate each target IP/hostname against SAD allowlist | Hard reject — tool call blocked |
| Auth Validator | Verify per-session HMAC token on every call | Hard reject — 401 returned |
| Risk Classifier | Assign risk level to each tool call based on playbook DB | Pause — escalate to human |
| Audit Logger | Write immutable, timestamped log entry for every call | Warning — execution continues |
| Rate Limiter | Enforce call frequency limits per tool type | Throttle — delay injection |
| Kill Switch | Accept kill signal and halt all executions | Terminate all active calls |

---

#### 3.2.3 Kali Linux MCP Tools

Kali tools are wrapped as MCP-compliant tool definitions and registered with the gateway. Each tool wrapper includes: the tool schema, input sanitization, execution handler, and output parser.

| Phase | Tool | ATT&CK Technique | Risk Level |
|---|---|---|---|
| Reconnaissance | nmap | T1046 Network Service Discovery | LOW |
| Reconnaissance | whois / dig | T1590 Gather Victim Network Info | LOW |
| Reconnaissance | whatweb | T1592 Gather Victim Host Info | LOW |
| Reconnaissance | theHarvester | T1589 Gather Victim Identity Info | LOW |
| Initial Access | hydra | T1110 Brute Force | MEDIUM |
| Initial Access | gobuster | T1083 File and Directory Discovery | LOW |
| Initial Access | nikto | T1190 Exploit Public-Facing Application | MEDIUM |
| Execution | msfconsole (via API) | T1059 Command and Scripting Interpreter | HIGH |
| Lateral Movement | impacket-psexec | T1570 Lateral Tool Transfer | HIGH |
| Credential Access | impacket-secretsdump | T1003 OS Credential Dumping | HIGH |
| Discovery | bloodhound-python | T1069 Permission Groups Discovery | MEDIUM |
| C2 | Caldera (REST) | T1105 Ingress Tool Transfer | HIGH |

---

#### 3.2.4 MITRE Caldera Integration

Caldera is deployed as a separate service within the engagement network. The Claude Code agent communicates with Caldera exclusively through the WAT MCP Gateway via a dedicated Caldera MCP tool wrapper. The agent can:

- Deploy Caldera agents (sandcat) to compromised hosts
- Execute specific ATT&CK abilities by ID
- Run full adversary emulation profiles (e.g., APT29, FIN7)
- Retrieve fact collection results (credentials, network mappings, host details)
- Trigger cleanup operations to remove indicators of compromise

---

#### 3.2.5 ATT&CK Playbook Database

A structured JSON/YAML database of 50+ playbook entries, each representing a testable ATT&CK technique. Example playbook entry schema:

```json
{
  "technique_id": "T1059.001",
  "name": "PowerShell",
  "tactic": "Execution",
  "risk_level": "HIGH",
  "tools": ["msfconsole", "caldera"],
  "command_template": "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp",
  "detection_artifacts": {
    "log_source": "Windows Event Log",
    "event_id": "4688",
    "siem_rule": "Suspicious PowerShell Execution"
  },
  "compliance_mapping": {
    "nist_csf": ["DE.CM-1"],
    "cis_controls": ["8.2"],
    "iso_27001": ["A.12.4.1"]
  },
  "requires_approval": true
}
```

---

### 3.3 Data Flow

#### 3.3.1 Engagement Lifecycle

| Step | Actor | Action | Gate |
|---|---|---|---|
| 1 | Operator | Load signed SAD into VS Code panel | SAD signature validation |
| 2 | WAT Gateway | Parse SAD, initialize scope allowlist and session token | Cryptographic verification |
| 3 | Operator | Select engagement profile (full, recon-only, lateral movement, etc.) | Profile validation |
| 4 | Claude Code | Query playbook DB, build ordered technique chain for selected profile | Risk classification |
| 5 | Claude Code | Begin executing chain: invoke MCP tools via gateway | Scope enforcement per call |
| 6 | WAT Gateway | Authorize, rate-limit, log, and forward each tool call | Audit write |
| 7 | Claude Code | Receive tool output, interpret result, decide next action | Chain length check |
| 8 | Approval Panel | Pause chain for HIGH/DESTRUCTIVE techniques, await operator approval | Human approval required |
| 9 | Claude Code | Continue chain after approval, or skip technique if denied | Resume or skip |
| 10 | Reporting Engine | On chain completion, compile audit log into structured report | Report validation |
| 11 | Operator | Review, annotate, and export final Assessment Report | Final QA |

---

### 3.4 Security Controls Architecture

#### 3.4.1 Defense-in-Depth for the Platform Itself

- All credentials captured during testing stored encrypted (AES-256-GCM), purged at engagement close
- Per-engagement isolated Docker containers with no shared volumes or networks across clients
- MCP Gateway session tokens rotate every 30 minutes; stale tokens cause hard rejection
- Operator workstation requires hardware MFA to access the Claude Code session
- Audit logs written to a separate, append-only volume inaccessible from the agent container
- The SAD is signed with the engagement lead's GPG key; the gateway verifies against a key ring

---

#### 3.4.2 Scope Enforcement Logic

```typescript
function validateToolCall(call: ToolCall, sad: SAD): ValidationResult {
  // 1. Session token validity
  if (!verifyHMAC(call.token, sad.session_secret)) {
    throw new Error('AUTH_FAILED');
  }

  // 2. Engagement window check
  const now = Date.now();
  if (now < sad.window_start || now > sad.window_end) {
    throw new Error('OUT_OF_WINDOW');
  }

  // 3. Target IP allowlist check
  for (const target of call.targets) {
    if (!isInAllowlist(target, sad.allowed_cidrs)) {
      throw new Error(`OUT_OF_SCOPE: ${target}`);
    }
    if (isInExcludeList(target, sad.excluded_ips)) {
      throw new Error(`EXCLUDED_TARGET: ${target}`);
    }
  }

  // 4. Technique category check
  const playbook = getPlaybook(call.technique_id);
  if (!sad.permitted_tactics.includes(playbook.tactic)) {
    throw new Error('TACTIC_NOT_PERMITTED');
  }

  return { authorized: true, risk_level: playbook.risk_level };
}
```

---

## 4. Build Plan & Milestones

### ▶ Phase 1: Foundation & Security Gateway *(Weeks 1–2)*

> All other phases depend on this. Do not proceed until Phase 1 is complete and independently tested.

- [ ] Set up monorepo structure: `/gateway`, `/agent`, `/playbooks`, `/caldera-client`, `/reporting`
- [ ] Build WAT MCP Gateway core: SAD validator, scope enforcer, auth validator, audit logger
- [ ] Implement kill switch (API endpoint + VS Code keybinding)
- [ ] Write gateway unit tests with simulated out-of-scope and out-of-window calls
- [ ] Validate audit log tamper-evidence with hash chaining

---

### ▶ Phase 2: Kali Tool Integration *(Weeks 2–3)*

- [ ] Wrap `nmap`, `whois`, `dig`, `theHarvester` as MCP tool definitions (recon-only)
- [ ] Test full call chain: VS Code → Claude Code → MCP Gateway → Kali tool → logged result
- [ ] Validate scope enforcement rejects out-of-scope targets at gateway level
- [ ] Wrap `gobuster`, `nikto` (LOW/MEDIUM tools) and add to gateway registry
- [ ] Conduct internal red team exercise against test lab using Phase 2 tools only

---

### ▶ Phase 3: ATT&CK Playbook Library *(Weeks 3–4)*

- [ ] Build playbook JSON schema and load/query module
- [ ] Populate initial 30 playbook entries covering Recon, Initial Access, Execution, Discovery
- [ ] Implement risk classifier in gateway using playbook DB
- [ ] Implement human approval gate for HIGH risk techniques
- [ ] Test approval gate with simulated HIGH technique calls

---

### ▶ Phase 4: Caldera Integration *(Weeks 4–5)*

- [ ] Deploy Caldera in isolated Docker network alongside WAT Gateway
- [ ] Build Caldera REST API client as MCP tool wrapper
- [ ] Register Caldera tool in gateway with HIGH risk classification
- [ ] Test agent deployment, ability execution, and fact retrieval via Claude Code
- [ ] Implement APT29 and FIN7 emulation profiles using Caldera + playbook chain

---

### ▶ Phase 5: HIGH-Risk Tool Integration *(Weeks 5–6)*

- [ ] Wrap `msfconsole`, `impacket`, `bloodhound` as HIGH risk MCP tools
- [ ] Enforce mandatory approval gate for all HIGH tools — no bypass path
- [ ] Test full lateral movement chain: recon → initial access → lateral movement → C2
- [ ] Conduct full internal engagement simulation with all tools active

---

### ▶ Phase 6: Reporting & Compliance Engine *(Weeks 6–7)*

- [ ] Build report generator: parse audit log → per-technique result objects
- [ ] Implement NIST CSF, CIS Controls v8, and ISO 27001 compliance mapping
- [ ] Generate PDF and DOCX report output with executive summary and gap analysis
- [ ] Build detection fidelity score metric (% techniques detected by client defenses)
- [ ] Conduct end-to-end test with full report output on lab environment

---

### ▶ Phase 7: Client Readiness & Hardening *(Weeks 7–8)*

- [ ] Security review of WAT platform itself (threat model, pentest the tool)
- [ ] Finalize SAD template and legal review of engagement authorization language
- [ ] Build engagement isolation: per-client Docker containers, no shared state
- [ ] Operator training documentation and runbook
- [ ] First authorized client pilot engagement with full audit and debrief

---

## 5. Repository Structure

```
wat-framework/
├── gateway/                    # WAT MCP Security Gateway
│   ├── src/
│   │   ├── sad-validator.ts    # SAD parsing & GPG signature verification
│   │   ├── scope-enforcer.ts   # IP allowlist & window validation
│   │   ├── auth.ts             # HMAC session token management
│   │   ├── risk-classifier.ts  # Technique risk level lookup
│   │   ├── audit-logger.ts     # Append-only hash-chained audit log
│   │   ├── kill-switch.ts      # Emergency stop handler
│   │   └── server.ts           # MCP gateway entrypoint
│   └── tests/
│
├── tools/                      # Kali Tool MCP Wrappers
│   ├── recon/
│   │   ├── nmap.ts
│   │   ├── theharvester.ts
│   │   └── whatweb.ts
│   ├── initial-access/
│   │   ├── hydra.ts
│   │   └── nikto.ts
│   ├── post-exploit/
│   │   ├── impacket.ts
│   │   ├── bloodhound.ts
│   │   └── msfconsole.ts
│   └── caldera-client.ts       # Caldera REST API wrapper
│
├── playbooks/                  # ATT&CK Playbook Library
│   ├── schema.json             # Playbook entry schema
│   ├── recon/
│   ├── initial-access/
│   ├── execution/
│   ├── lateral-movement/
│   ├── credential-access/
│   └── index.ts                # Playbook loader & query engine
│
├── agent/                      # Claude Code Agent Configuration
│   ├── CLAUDE.md               # Agent instructions & constraints
│   ├── system-prompt.md        # Base system prompt for WAT sessions
│   └── engagement-profiles/    # Pre-built engagement chain templates
│
├── reporting/                  # Report Generation Engine
│   ├── src/
│   │   ├── log-parser.ts       # Audit log → structured result objects
│   │   ├── compliance-mapper.ts # Results → NIST/CIS/ISO gaps
│   │   ├── score-engine.ts     # Detection fidelity scoring
│   │   └── report-builder.ts   # DOCX/PDF report generator
│   └── templates/
│
├── sad-templates/              # Scope Authorization Document templates
│   └── engagement-sad.template.json
│
├── docker/                     # Containerization
│   ├── gateway.Dockerfile
│   ├── caldera.Dockerfile
│   └── docker-compose.yml
│
└── docs/                       # Documentation
    ├── operator-runbook.md
    ├── sad-guide.md
    └── threat-model.md
```

---

## 6. Compliance & Legal Requirements

### 6.1 Pre-Engagement Requirements

The following must be in place before any WAT session is initiated. These are non-negotiable platform requirements, not procedural guidelines.

| Requirement | Form | Stored Where | Verified By |
|---|---|---|---|
| Signed Scope Authorization Document | GPG-signed JSON | SAD vault (encrypted) | Gateway SAD validator |
| Master Services Agreement with pen test clause | Legal document | Client folder | Engagement lead |
| Rules of Engagement (RoE) document | PDF signed by both parties | Client folder | Engagement lead |
| Emergency contact list (client IT, CISO, NOC) | Structured contact JSON | Loaded into gateway | Operator |
| Out-of-scope system list (production, HA systems) | IP list in SAD `excluded_ips` | SAD file | Gateway scope enforcer |

---

### 6.2 Data Handling During Engagement

- Captured credentials are encrypted immediately on capture; plaintext never written to disk
- Network captures (pcap) are stored encrypted and destroyed within 24 hours of engagement close
- All engagement data is isolated per-client; no cross-client data access is architecturally possible
- Engagement data may only be retained beyond 30 days with explicit written client consent
- Client data is never used to train AI models or improve the WAT system without explicit consent

> ⚠️ **CRITICAL:** The WAT Framework must never be used without a cryptographically valid Scope Authorization Document. Attempting to bypass this control is a violation of computer fraud laws in all major jurisdictions and Anthropic's acceptable use policy.

---

### 6.3 Incident Response During Engagement

If the agent causes unintended impact (service disruption, data exposure, out-of-scope access):

1. Activate the kill switch immediately from VS Code or CLI
2. Contact the client emergency contact list within 15 minutes
3. Preserve the audit log in its current state — do not delete or modify
4. Initiate incident response procedure per the RoE document
5. Generate an incident report from the audit log within 24 hours

---

## 7. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Agent executes out-of-scope target | Medium | Critical | Hard scope enforcement in gateway — not agent-layer only |
| Client credential data exposed | Low | Critical | AES-256 encryption at capture; automated purge at close |
| Engagement causes production outage | Low | Critical | Exclude production CIDRs in SAD; human approval for HIGH techniques |
| Claude Code hallucinates tool parameters | Medium | High | Gateway validates all parameters against tool schema before execution |
| Caldera agent persists post-engagement | Medium | High | Cleanup operation mandatory in engagement close procedure |
| Audit log tampered post-engagement | Low | High | Hash-chained log on append-only volume; tamper detection on export |
| SAD stolen and reused | Low | Critical | SAD has engagement window; expired SAD hard-rejected by gateway |
| Platform itself gets compromised | Low | Critical | Threat model + pentest of WAT platform prior to client use |

---

## 8. Glossary

| Term | Definition |
|---|---|
| WAT | Weaponized Automation Testing — the name of this framework |
| SAD | Scope Authorization Document — signed JSON file authorizing an engagement |
| MCP | Model Context Protocol — Anthropic's standard for exposing tools to Claude |
| ATT&CK | Adversarial Tactics, Techniques & Common Knowledge — MITRE's threat framework |
| TTP | Tactics, Techniques, and Procedures — adversary behavior patterns |
| Caldera | MITRE's open-source adversary emulation platform |
| Kill Chain | Ordered sequence of attack phases from recon through impact |
| CSCV | Continuous Security Control Validation — the capability category WAT belongs to |
| RoE | Rules of Engagement — document governing engagement conduct |
| HMAC | Hash-based Message Authentication Code — used for session token validation |
| CIDR | Classless Inter-Domain Routing — IP range notation used in SAD allowlists |
| Detection Fidelity Score | Percentage of emulated techniques that triggered a client defense alert |

---

*WAT Framework PRD v1.0 | Confidential | March 2026*
