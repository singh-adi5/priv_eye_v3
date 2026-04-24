# Security Policy

## Supported versions

Priv-Eye is in active development. Only `main` receives security fixes at this stage.

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.**

Email: `security@priv-eye.example` (replace with a real address when published)
PGP: fingerprint `TODO — generate before public release`

Include:
- A description of the issue and its impact
- Steps to reproduce or a proof-of-concept
- Your disclosure timeline expectations

We will acknowledge receipt within 72 hours and provide a remediation timeline within 7 days.

## Scope

In scope:
- `api/` (FastAPI backend)
- `agent/` (priveye-agent CLI)
- Cryptographic controls (JWT, HMAC)
- Authorization / authentication logic

Out of scope:
- Self-XSS in the demo dashboard
- DoS via rate-limit thresholds configured in local dev
- Vulnerabilities in dependencies without a demonstrated reachable code path — please use `pip-audit` and open a PR upgrading the affected dep

## Safe harbor

Good-faith security research performed in accordance with this policy will not result in legal action. Please do not access data you do not own, and do not disrupt the service.
