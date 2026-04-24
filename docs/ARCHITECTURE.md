# Priv-Eye v3 — Architecture

## Overview

Three deployable components communicate over HTTPS:

```
Target host
  └─ priveye-agent (CLI)
       │  HMAC-signed POST /api/v1/scans
       ▼
   priv-eye API (FastAPI)
       │  sklearn RF inference  │  SQLite / Postgres
       │  Gemini POST (optional)│  Audit log (append-only)
       ▼
   Dashboard (Starlette + Jinja2 + HTMX)
       │  JWT cookie session
       ▼
  Browser
```

---

## Data flow — scan ingest

```
Agent                      API                         DB
  │                          │                          │
  ├─ uname / find / sudo-l   │                          │
  │  (recon.py)              │                          │
  ├─ HMAC sign payload ──────►                          │
  │                          ├─ verify timestamp+nonce  │
  │                          ├─ load feature vector     │
  │                          ├─ RF.predict_proba() ─────►
  │                          ◄─ [LOW,MED,HIGH] probs ───┤
  │                          ├─ write Scan row ─────────►
  │                          ├─ write AuditLog ─────────►
  ◄─ AnalysisResult ─────────┤                          │
```

---

## Trust boundaries

| Boundary | What crosses it | Control |
|---|---|---|
| Agent → API | Telemetry JSON | HMAC-SHA256, nonce replay protection, timestamp window |
| Browser → Dashboard | Session | HTTPOnly/SameSite cookie with JWT |
| Dashboard → API | User actions | Bearer JWT forwarded by proxy route |
| API → Gemini | Sanitised structured prompt | Control-char strip, banned-prefix filter, quota |
| API → DB | ORM queries | Parameterised (SQLAlchemy), owner-scoped selects |

---

## Component responsibilities

### `agent/`

- **`recon.py`** — No shell=True. Probes `/usr/bin`, `/usr/sbin` etc. via explicit `find` argv.
  Returns `ReconResult` with `degraded_probes` for soft failures.
- **`transport.py`** — Signs canonical `timestamp\nnonce\nbody` string with HMAC-SHA256.
  Raises `TransportError` on any non-201; never retries automatically (caller decides policy).
- **`cli.py`** — Typer entrypoint. `scan` (collect + upload), `selftest` (health ping), `version`.

### `api/`

- **`core/auth.py`** — Password hashing (Argon2id), JWT issue/verify (HS256 dev / RS256 prod),
  HMAC agent-key verification, account lockout after N failed logins.
- **`core/models.py`** — `User`, `Host`, `Scan`, `AuditLog`, `RefreshToken`, `Nonce`.
  Scans are tombstoned (soft-deleted); AuditLog rows are never deleted at the app layer.
- **`ml/features.py`** — Deterministic feature vector: 19 columns, same order at train + infer.
- **`ml/train.py`** — RandomForestClassifier(300, max_depth=7, balanced), synthetic 1 500-sample
  distribution, writes `model.pkl` + `model_meta.json`.
- **`ml/infer.py`** — Thread-safe `_ModelHolder`. SHA256 integrity check at load. Returns
  `probabilities`, `feature_importances`, `reasons`, `model_version`.
- **`routers/scans.py`** — Ingest (agent, HMAC auth) + history (user, JWT auth).
- **`routers/insights.py`** — Gemini synthesis behind a 30/day/user audit-log quota.

### `dashboard/`

- **`app.py`** — Starlette server. Renders Jinja2 templates server-side; `/proxy/*` relays
  authenticated API calls from the browser.
- **`templates/`** — `login.html` (sign-in / register), `dashboard.html` (bento grid).
- **`static/app.js`** — Add-host form, host filter, detail drawer with real ML numbers,
  insight generation.

---

## Architecture decision records

### ADR-01: FastAPI over Express
**Decision:** Replace v2's Express `server.ts` with Python FastAPI.
**Rationale:** The ML stack (sklearn, numpy, pandas) is native Python. Eliminating the
language boundary (Python model ↔ Node server) removes the largest integration risk.

### ADR-02: SQLite default, Postgres upgrade path
**Decision:** SQLite via `aiosqlite` for development; DATABASE_URL swaps to asyncpg for prod.
**Rationale:** Zero-ops local start; Alembic migrations are DB-agnostic.

### ADR-03: HMAC over mTLS for agent auth
**Decision:** HMAC-SHA256 with per-host key rather than mTLS client certificates.
**Rationale:** mTLS requires a PKI; HMAC is self-contained and revocable by rotating one
environment variable on the target host. Replay protection (nonce + timestamp window) covers
the main HMAC weakness.

### ADR-04: Server-side dashboard, no SPA framework
**Decision:** Jinja2 + HTMX instead of React for the dashboard.
**Rationale:** v2's React bundle required a build pipeline and shipped fabricated hardcoded
metrics. A server-rendered dashboard keeps every displayed value server-computed and
eliminates the stale-frontend-data failure mode.

### ADR-05: Gemini as a presentation layer only
**Decision:** Gemini receives structured fields (risk enum, score, reasons list),
never raw free-text from the host.
**Rationale:** Prevent prompt injection via hostname or sudoers output. The ML score is the
ground truth; Gemini translates it into executive language.
