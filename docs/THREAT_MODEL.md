# Priv-Eye Threat Model

**Methodology:** STRIDE over Data Flow Diagrams. Trust boundaries drawn between (agent ↔ API), (API ↔ DB), (API ↔ Gemini). Revision: v0.1 (2026-04-23).

## 1. System scope

Priv-Eye ingests host telemetry from distributed agents, scores it with a Random Forest, and persists scan + audit records. The **crown jewel** is the `scans` table and its audit trail — if an attacker can forge or suppress scans, they can hide compromise from the security team using this tool.

## 2. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | `scans` records | Authoritative posture history; compliance evidence |
| A2 | `audit_log` records | Tamper-evidence for who did what, when |
| A3 | Per-host HMAC keys | Allow agents to authenticate scan uploads |
| A4 | User password hashes | Argon2id digests; loss = credential stuffing attacks |
| A5 | `JWT_SECRET` | Signs access tokens; loss = full impersonation |
| A6 | `model.pkl` | The trained Random Forest; loss of integrity = wrong risk scores |
| A7 | `GEMINI_API_KEY` | Costs money if abused; prompt-injection surface |

## 3. Trust boundaries

```
┌─────────────────────┐    TB-1    ┌────────────────────────┐   TB-2   ┌──────────────┐
│ Target host (agent) │  HMAC+JWT  │ FastAPI (app container)│  SQL     │ Database     │
│ [untrusted]         │────────────│ [semi-trusted]         │──────────│ [trusted]    │
└─────────────────────┘            └───────────┬────────────┘          └──────────────┘
                                               │
                                               │ TB-3: HTTPS to Gemini
                                               ▼
                                        ┌──────────────┐
                                        │ Gemini API   │
                                        │ [external]   │
                                        └──────────────┘
```

- **TB-1 (agent ↔ API):** agent is on hosts we do not fully control. Treat all scan payloads as hostile until HMAC + replay window verified.
- **TB-2 (API ↔ DB):** DB is inside the same trust zone as the API but SQL parameterization still enforced.
- **TB-3 (API ↔ Gemini):** outbound only; never forward raw user-controlled strings into prompts without templating.

## 4. STRIDE entries

Each entry lists the threat, where it lives, the mitigation, and the control tag (see [`CONTROLS.md`](CONTROLS.md)).

### Spoofing

| T-ID | Threat | Location | Mitigation | Control |
|---|---|---|---|---|
| S1 | Attacker forges a scan as another host | TB-1 | Per-host HMAC-SHA256 key; `X-PrivEye-Signature` header validated before any business logic | ASVS V2.6 · NIST IA-3(1) |
| S2 | Attacker steals JWT from browser storage | dashboard | `HttpOnly; Secure; SameSite=Strict` cookies; 15-min access token; refresh rotation | ASVS V3.4 · NIST IA-2 |
| S3 | Credential stuffing against /login | API | Argon2id hashing, per-IP rate limit, generic error message, account lockout after N failures | ASVS V2.2 · NIST IA-5 |

### Tampering

| T-ID | Threat | Location | Mitigation | Control |
|---|---|---|---|---|
| T1 | MITM modifies scan payload | TB-1 | HMAC over full request body + timestamp; TLS required in prod | ASVS V9.1 · NIST SC-8 |
| T2 | Replay of old scan to mask current compromise | TB-1 | `X-PrivEye-Timestamp` must be within ±5min; nonce tracked for 10min | ASVS V2.9 · NIST SI-7 |
| T3 | Direct DB write bypassing API | TB-2 | DB user has narrow grants; no network access to DB from outside app container | ASVS V1.11 · NIST AC-3 |
| T4 | Swap of `model.pkl` on disk | deployment | Model file hash pinned in config; verified at load; CI publishes SHA256 | NIST SI-7(1) · SSDF PW.6.2 |

### Repudiation

| T-ID | Threat | Location | Mitigation | Control |
|---|---|---|---|---|
| R1 | User deletes their own scan to hide bad posture | API | `audit_log` is append-only; DELETE on scans writes a tombstone, not a hard delete; auditor role can see tombstones | ASVS V7.1 · NIST AU-9 |
| R2 | Authentication events not logged | API | Every login, token refresh, failed auth written with user-ID, IP, UA, timestamp | ASVS V7.2 · NIST AU-2 |

### Information Disclosure

| T-ID | Threat | Location | Mitigation | Control |
|---|---|---|---|---|
| I1 | `GEMINI_API_KEY` leaks into client bundle | frontend | No client-side LLM calls; key only in server env; `.env` in `.gitignore` | ASVS V14.1 · NIST SC-28 |
| I2 | Stack traces leak paths/versions | API | `DEBUG=false` in prod; generic 500 responses; structured logs go only to the audit sink | ASVS V7.4 · NIST SI-11 |
| I3 | User A reads user B's scans | API | Every read query scopes by `user_id = current_user.id`; tested in `test_authorization.py` | ASVS V4.1 · NIST AC-3 |
| I4 | Prompt injection extracts system prompt / other users' data from Gemini | /insights | Gemini gets *only* the numeric+enum fields; freeform strings (hostname) stripped of control chars and length-capped; no cross-user data in prompt | ASVS V5.1 · NIST SI-10 |

### Denial of Service

| T-ID | Threat | Location | Mitigation | Control |
|---|---|---|---|---|
| D1 | Flood of scans exhausts DB | /api/v1/scans | Rate limit per host-ID (60/min) and per IP (300/min); SQLite→Postgres path documented | ASVS V13.1 · NIST SC-5 |
| D2 | Gemini quota exhaustion | /api/v1/insights | 30/user/day; feature-flag disables endpoint entirely if quota breached | ASVS V11.1 · NIST SC-6 |
| D3 | Algorithmic complexity attack via crafted feature vector | /ml/infer | Pydantic constrains integer ranges and list lengths before model.predict runs | ASVS V5.2 · NIST SI-10 |

### Elevation of Privilege

| T-ID | Threat | Location | Mitigation | Control |
|---|---|---|---|---|
| E1 | Standard user grants themselves auditor role | API | Role stored in JWT claim signed by server; role changes only via admin endpoint gated on ADMIN role | ASVS V4.2 · NIST AC-6 |
| E2 | Container breakout via app code | deployment | Non-root user in Dockerfile, read-only rootfs, `no-new-privileges`, dropped capabilities | ASVS V14.1.3 · NIST SC-39 |
| E3 | Agent runs as root on target and exposes RCE | agent | Agent is read-only (shell commands via list args, never shell=True); can run as non-root if sudoers read rights present; no network listener | ASVS V5.3 · NIST SI-10 |

## 5. Out-of-scope (declared gaps)

Honesty beats pretending:

- **Supply-chain attacks on pip dependencies** — mitigated with `pip-audit` in CI and pinned versions, but not fully (no reproducible builds, no sigstore).
- **Physical access to the agent host** — if an attacker has root on the target, they can feed the agent lying data. Priv-Eye detects *configuration* risk, not rootkits.
- **Firestore/Firebase prototype** — not in scope for v3; the v2 UI remains as a reference.
- **Multi-tenant org isolation beyond per-user** — single-tenant today; org-level RBAC is v3.1.

## 6. Attacker personas

| Persona | Motivation | Capability | What they try first |
|---|---|---|---|
| External opportunist | Bot / scanner | Unauth probe of public endpoints | `/api/v1/auth/login` brute force, `/api/v1/scans` without auth |
| Compromised host | Escalated local attacker on a scanned host | Knows the host's HMAC key | Forge benign scans to mask their presence (→ mitigated by R1 tombstones + drift detection) |
| Malicious insider | Legitimate user with standard role | Valid JWT, knows own data | Attempt horizontal privilege escalation to see peer scans (→ mitigated by I3 query scoping) |
| Upstream poisoned dependency | Supply-chain | Arbitrary code in a dependency | Would subvert CI; mitigated by pinned versions + `pip-audit` + minimal deps, not eliminated |
