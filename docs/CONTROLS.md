# Security Controls Map

Each row maps a **control requirement** (OWASP ASVS v4.0.3, NIST SP 800-53 Rev. 5) to the **file and function** that implements it. This is the document to open during interviews when asked "show me where you enforce X."

Framework abbreviations:
- **ASVS** — [OWASP Application Security Verification Standard v4.0.3](https://owasp.org/www-project-application-security-verification-standard/)
- **NIST** — [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- **SSDF** — [NIST SP 800-218 Secure Software Development Framework](https://csrc.nist.gov/publications/detail/sp/800-218/final)

---

## V1 — Architecture, Design, Threat Modeling

| # | Requirement | ASVS | NIST | Implementation |
|---|---|---|---|---|
| 1 | Documented threat model exists and is versioned | V1.1.2 | PL-8 | [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) |
| 2 | Trust boundaries explicitly identified | V1.1.4 | SA-17 | `THREAT_MODEL.md` §3 |
| 3 | Secure defaults in config | V1.1.5 | CM-7 | `priveye_api/core/config.py` — `DEBUG=False`, `JWT_ALGORITHM="HS256"` with RS256 ready |

## V2 — Authentication

| # | Requirement | ASVS | NIST | Implementation |
|---|---|---|---|---|
| 4 | Passwords hashed with a modern KDF | V2.4.1 | IA-5(1) | `priveye_api/core/auth.py::hash_password` (argon2-cffi) |
| 5 | Rate-limiting on authentication endpoints | V2.2.1 | AC-7 | `priveye_api/core/security.py::rate_limit_login` |
| 6 | Generic auth failure messages | V2.2.3 | IA-6 | `priveye_api/routers/auth.py` — single 401 message for all failure modes |
| 7 | Per-host HMAC key for agent upload | V2.6 | IA-3(1) | `priveye_api/core/auth.py::verify_hmac` |
| 8 | Replay-attack prevention | V2.9 | SI-7 | `priveye_api/core/auth.py::verify_timestamp_and_nonce` |

## V3 — Session Management

| # | Requirement | ASVS | NIST | Implementation |
|---|---|---|---|---|
| 9 | Short-lived access tokens | V3.3 | IA-11 | 15-minute JWT expiry, refresh rotation — `auth.py::create_access_token` |
| 10 | Token revocation on logout | V3.3.3 | AC-12 | `refresh_tokens` table — revoked on logout/rotation |

## V4 — Access Control

| # | Requirement | ASVS | NIST | Implementation |
|---|---|---|---|---|
| 11 | Authorization enforced server-side | V4.1.1 | AC-3 | Every router dependency uses `Depends(get_current_user)` |
| 12 | Queries scoped by `user_id` | V4.1.3 | AC-4 | `priveye_api/routers/scans.py` — `WHERE user_id = :user_id` in every read |
| 13 | Role-based access via signed claim | V4.2 | AC-6 | JWT `role` claim, enforced by `require_role` dependency |

## V5 — Validation, Sanitization, Encoding

| # | Requirement | ASVS | NIST | Implementation |
|---|---|---|---|---|
| 14 | All inputs validated by schema | V5.1.3 | SI-10 | Pydantic models in `priveye_api/schemas.py` |
| 15 | Integer ranges + string length caps | V5.1.4 | SI-10(3) | `Field(ge=0, le=1000)`, `constr(max_length=256)` throughout schemas |
| 16 | SQL via parameterized queries only | V5.3.4 | SI-10(5) | SQLAlchemy 2.0 ORM — no raw SQL |
| 17 | Prompt-injection mitigation for LLM | V5.1 | SI-10 | `priveye_api/routers/insights.py::sanitize_for_prompt` |

## V7 — Error Handling and Logging

| # | Requirement | ASVS | NIST | Implementation |
|---|---|---|---|---|
| 18 | Structured audit log for auth events | V7.1.1 | AU-2 | `priveye_api/core/audit.py::AuditLogger` — JSON lines |
| 19 | Logs exclude sensitive data | V7.1.3 | AU-3 | `core/audit.py` redacts tokens, passwords, HMAC keys |
| 20 | Tamper-evident log (append-only tombstones) | V7.2.1 | AU-9 | DELETE scans writes `deleted_at` rather than removing row |
| 21 | Generic error responses in prod | V7.4 | SI-11 | `main.py::global_exception_handler` — no stack traces to client |

## V9 — Communications

| # | Requirement | ASVS | NIST | Implementation |
|---|---|---|---|---|
| 22 | TLS enforced in prod | V9.1.2 | SC-8 | Uvicorn behind reverse proxy; HSTS header via `security.py::add_security_headers` |
| 23 | HMAC-signed agent traffic | V9.2.1 | SC-8(1) | `core/auth.py::verify_hmac` |

## V11 — Business Logic

| # | Requirement | ASVS | NIST | Implementation |
|---|---|---|---|---|
| 24 | Quotas on expensive operations | V11.1.4 | SC-6 | Gemini call capped per user/day — `routers/insights.py` |
| 25 | ML input bounded to prevent algorithmic DoS | V11.1.6 | SI-10 | Feature-vector size + value ranges validated pre-inference |

## V13 — API

| # | Requirement | ASVS | NIST | Implementation |
|---|---|---|---|---|
| 26 | Rate limiting on API | V13.1 | SC-5 | `core/security.py` — slowapi per-IP + per-host limits |
| 27 | CORS explicitly configured | V13.2.1 | SC-7 | Allowlist in `config.py`; not wildcard |

## V14 — Configuration

| # | Requirement | ASVS | NIST | Implementation |
|---|---|---|---|---|
| 28 | Secrets in env, never in code | V14.1.1 | IA-5(7) | `.env.example` shows keys, `.gitignore` excludes `.env` |
| 29 | Container runs as non-root | V14.1.3 | SC-39 | `api/Dockerfile` — `USER priveye` |
| 30 | Dependencies scanned in CI | V14.2.1 | SA-11 | `.github/workflows/ci.yml` — pip-audit, trivy, gitleaks |
| 31 | Security headers (CSP, HSTS, X-Frame-Options) | V14.4 | SC-18 | `core/security.py::add_security_headers` middleware |

---

## ML-specific controls (bridging ASVS gaps)

OWASP ASVS doesn't deeply cover ML. These controls fill that gap, referencing [OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/) and [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework).

| # | Requirement | Framework | Implementation |
|---|---|---|---|
| 32 | Model artifact integrity verified at load | NIST AI RMF MANAGE-1.3 | `ml/infer.py::_verify_model_hash` — compares against `MODEL_SHA256` env |
| 33 | Feature-vector bounds enforced | OWASP ML05 | Pydantic constraints + `ml/infer.py::_validate_features` |
| 34 | Model version recorded with every prediction | NIST AI RMF MAP-4.1 | `scans.model_version` column; surfaced in API response |
| 35 | Adversarial test cases in CI | OWASP ML02 | `tests/test_ml_robustness.py` — crafted inputs must not flip class |
| 36 | Training reproducibility (seed, params, data hash) | SSDF PW.6 | `scripts/train_model.py` writes `model_meta.json` alongside `model.pkl` |

---

## Gap log (honest about what isn't built yet)

| # | Requirement | ASVS | Gap | Owner |
|---|---|---|---|---|
| G1 | Multi-factor authentication | V2.8 | Password-only today | v3.2 |
| G2 | Key rotation for HMAC host keys | — | Keys are permanent; need rotation API | v3.1 |
| G3 | Org-level RBAC (currently per-user) | V4.2 | Single-tenant | v3.1 |
| G4 | WAF / API gateway | V13.1.3 | Bring-your-own in prod | deployment |
| G5 | SBOM publication | SSDF PS.3 | Run `syft` in CI and attach to releases | v3.1 |

Gaps are tracked as GitHub issues with labels `control-gap` and the ASVS ID.
