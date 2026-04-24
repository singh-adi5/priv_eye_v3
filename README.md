# Priv-Eye

**ML-backed Linux privilege-posture engine with a distributed agent, a signed ingest API, and a drift-aware scoring model.**

Priv-Eye assesses how exposed a Linux host is to privilege-escalation attacks. Lightweight agents collect real host telemetry (kernel, SUID surface, sudoers posture), a central API verifies the payload cryptographically, a scikit-learn Random Forest scores the host as LOW / MEDIUM / HIGH, and an audit trail preserves every scan for compliance review.

This is the third iteration of the project:

| Version | What it was | Status |
|---|---|---|
| **v1** ([`singh-adi5/priv-eye`](https://github.com/singh-adi5/priv-eye)) | Python CLI, real recon, real sklearn RF. No UI, no auth, single-host. | Reference — the model lives here. |
| **v2 (archived)** | React 19 + Firebase + Gemini UI demo. Beautiful dashboard, but the ML engine from v1 was not carried over — the scorer was a hand-coded `if/else`. | Design exploration. UI language retained; backend discarded. |
| **v3 (this repo)** | FastAPI + real v1 ML + HMAC-signed agent + JWT auth + audit log + OWASP ASVS / NIST SP 800-53 aligned. | Current. |

---

## Why this exists

Traditional privilege-audit tools (LinPEAS, Lynis, lshw) produce walls of text that require an expert to interpret. Aggregators (Splunk, ELK) ingest the output but don't *score* it. LLM-only tools are non-deterministic and non-auditable. The gap this project fills: **reproducible, explainable, longitudinal posture scoring** — with the model's decision surface documented and the data path tamper-evident.

## Design principles

1. **The model is real and interpretable.** Random Forest, feature importances reported on every prediction, metrics pinned in CI.
2. **Nothing is faked in the UI.** Every displayed number traces to a computation.
3. **Every security claim maps to a control.** See [`docs/CONTROLS.md`](docs/CONTROLS.md) — OWASP ASVS v4.0.3 and NIST SP 800-53 Rev. 5 control IDs next to the code that implements them.
4. **Threats are documented before code.** See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
5. **The agent is zero-trust.** Host-scoped HMAC keys, replay protection, no long-lived secrets in recon code.

## Repo layout

```
priv-eye/
├── api/                         FastAPI backend (auth, scans, ML, audit)
│   ├── priveye_api/
│   │   ├── routers/             /api/v1/* endpoints
│   │   ├── ml/                  sklearn RF trainer + inference (ported from v1)
│   │   └── core/                auth, config, db, security headers, audit log
│   └── tests/
├── agent/                       priveye-agent CLI (recon + HMAC transport)
├── dashboard/                   Jinja + HTMX server-rendered UI (optional)
├── docs/
│   ├── THREAT_MODEL.md          STRIDE analysis, trust boundaries
│   ├── CONTROLS.md              OWASP ASVS + NIST SP 800-53 mapping
│   ├── ARCHITECTURE.md          Data flow, sequence diagrams, ADRs
│   └── DEPLOYMENT.md            Prod hardening notes
├── scripts/
│   └── train_model.py           One-shot training script → model.pkl
├── .github/workflows/
│   ├── ci.yml                   pytest + ruff + mypy + bandit + pip-audit
│   └── security.yml             gitleaks + trivy + scheduled SCA
├── docker-compose.yml           One-command local stack
├── SECURITY.md                  Vulnerability disclosure policy
└── LICENSE
```

## Quick start (local)

```bash
# 1. Clone and configure
git clone <this-repo> && cd priv-eye
cp .env.example .env
# Edit .env — set JWT_SECRET, optionally GEMINI_API_KEY

# 2. Train the model
docker compose run --rm api python -m priveye_api.ml.train

# 3. Bring up the API
docker compose up --build

# 4. Register a host and get an agent token
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"PickAStrongPassword!1"}'

curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"PickAStrongPassword!1"}'
# → returns access_token

curl -X POST http://localhost:8000/api/v1/hosts \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"prod-db-01","environment":"prod"}'
# → returns {host_id, hmac_key} — store both on the target host

# 5. Scan a host
pip install -e agent/
PRIVEYE_API=http://localhost:8000 \
PRIVEYE_HOST_ID=<host_id> \
PRIVEYE_HMAC_KEY=<hmac_key> \
priveye-agent scan
```

## What to look at first (if you're an interviewer or reviewer)

1. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — every asset, trust boundary, and STRIDE entry with mitigation.
2. [`docs/CONTROLS.md`](docs/CONTROLS.md) — OWASP ASVS + NIST control mapping to specific files and functions.
3. [`api/priveye_api/core/auth.py`](api/priveye_api/core/auth.py) — JWT issuance, password hashing, HMAC verification for the agent.
4. [`api/priveye_api/ml/infer.py`](api/priveye_api/ml/infer.py) — how the RF is loaded and scored, and how features are surfaced.
5. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — the quality gate.

## License

MIT. See [`LICENSE`](LICENSE).
