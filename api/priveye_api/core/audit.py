"""
Structured, redacted audit logging.

Everything security-relevant flows through `AuditLogger.emit`. The same event
is written to both (a) a JSON-lines structured log (for SIEM ingest) and
(b) the `audit_log` table (for in-app review by auditors).

Control refs:
- ASVS V7.1.1 / NIST AU-2, AU-3 — what to log
- ASVS V7.1.3 — never log secrets
- ASVS V7.2.1 / NIST AU-9 — tamper-evidence via append-only
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditLog, generate_id

_log = logging.getLogger("priveye.audit")

# Anything matching these keys in a details dict is redacted.
_REDACT_KEYS = {
    "password",
    "password_hash",
    "new_password",
    "token",
    "access_token",
    "refresh_token",
    "jwt",
    "hmac_key",
    "x-priveye-key",
    "authorization",
    "secret",
    "api_key",
}

_JWT_PATTERN = re.compile(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("[REDACTED]" if k.lower() in _REDACT_KEYS else _redact(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str):
        return _JWT_PATTERN.sub("[REDACTED-JWT]", value)
    return value


class AuditLogger:
    """Use via dependency injection in routers."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def emit(
        self,
        *,
        event_type: str,
        outcome: str,
        actor_user_id: str | None = None,
        actor_ip: str | None = None,
        actor_ua: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        safe_details = _redact(details or {})

        # (a) structured log for SIEM
        _log.info(
            json.dumps(
                {
                    "event_type": event_type,
                    "outcome": outcome,
                    "actor_user_id": actor_user_id,
                    "actor_ip": actor_ip,
                    "actor_ua": actor_ua,
                    "details": safe_details,
                },
                default=str,
            )
        )

        # (b) in-app append-only record
        row = AuditLog(
            id=generate_id(),
            actor_user_id=actor_user_id,
            actor_ip=actor_ip,
            actor_ua=actor_ua[:512] if actor_ua else None,
            event_type=event_type[:64],
            outcome=outcome[:16],
            details=safe_details,
        )
        self._db.add(row)
        # Flush but leave commit to the enclosing transaction so the audit
        # row shares fate with the action it describes (commit or rollback together).
        await self._db.flush()
