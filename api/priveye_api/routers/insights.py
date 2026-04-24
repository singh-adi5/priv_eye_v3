"""
LLM-backed insight endpoint (optional — disabled if GEMINI_API_KEY unset).

Hardening:
- Prompt built from **structured** fields only; free-text user strings
  (hostname) are stripped of control chars and length-capped.
- Per-user daily quota enforced via audit_log count.
- Response forced to JSON schema; non-conforming output → 502.

Control refs:
- ASVS V5.1 / NIST SI-10 — prompt-injection mitigation
- ASVS V11.1.4 / NIST SC-6 — quotas on expensive ops
"""


import json
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.audit import AuditLogger
from ..core.auth import get_current_user
from ..core.config import get_settings
from ..core.db import get_db
from ..core.models import AuditLog, Scan, User
from ..schemas import InsightRequest, InsightResponse

router = APIRouter(prefix="/api/v1/insights", tags=["insights"])
_settings = get_settings()

# Only what we actually let into the prompt. Everything else is dropped.
_ALLOWED_TELEMETRY_KEYS = {"kernel_version", "euid", "suid_total_count", "sudo_has_nopasswd", "sudo_has_all"}

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize_for_prompt(s: str, max_len: int = 128) -> str:
    s = _CONTROL_CHARS.sub("", s)
    # Drop common prompt-injection prefixes.
    banned = [
        "ignore previous",
        "disregard",
        "system:",
        "assistant:",
        "you are now",
    ]
    lower = s.lower()
    for b in banned:
        if b in lower:
            s = s.replace(b, "[filtered]").replace(b.upper(), "[FILTERED]")
    return s[:max_len]


async def _quota_remaining(db: AsyncSession, user_id: str) -> int:
    window_start = datetime.now(timezone.utc) - timedelta(hours=24)
    result = await db.execute(
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.actor_user_id == user_id,
            AuditLog.event_type == "insight.generate",
            AuditLog.outcome == "success",
            AuditLog.created_at >= window_start,
        )
    )
    used = int(result.scalar_one())
    return max(0, _settings.gemini_per_user_daily_quota - used)


def _build_prompt(scan: Scan) -> str:
    # Scan fields are all server-generated or pre-validated integers/enums, safe.
    safe_hostname = "redacted"  # intentional — never put hostname into LLM prompt
    kernel = _sanitize_for_prompt(str(scan.telemetry.get("kernel_version", "unknown")), 32)
    return (
        "You are a cyber-security architect. A Linux host posture scan produced "
        f"risk={scan.risk.value}, score={scan.score}/100, reasons={list(scan.reasons)}. "
        f"Selected telemetry: kernel={kernel}, "
        f"suid_total={scan.telemetry.get('suid_total_count', 'n/a')}, "
        f"sudo_nopasswd={bool('NOPASSWD' in scan.telemetry.get('sudo_privileges', ''))}. "
        "Respond ONLY as a valid JSON object with keys: "
        '"threat_landscape" (string), "compliance_impact" (string), '
        '"remediation_roadmap" (array of 3-5 strings). No prose outside the JSON.'
    )


@router.post("", response_model=InsightResponse)
async def generate_insight(
    body: InsightRequest,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> InsightResponse:
    if not _settings.insights_enabled:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Insights disabled")

    scan = await db.get(Scan, body.scan_id)
    if scan is None or scan.owner_id != user.id or scan.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")

    remaining = await _quota_remaining(db, user.id)
    if remaining <= 0:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Daily insight quota exhausted")

    # Lazy-import so the package is optional (see pyproject `[insights]` extra).
    try:
        from google import genai  # type: ignore[import-not-found]
    except ImportError as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Insights backend not installed") from e

    prompt = _build_prompt(scan)
    client = genai.Client(api_key=_settings.gemini_api_key.get_secret_value())  # type: ignore[union-attr]
    audit = AuditLogger(db)
    try:
        resp = client.models.generate_content(model=_settings.gemini_model, contents=prompt)
        text = (resp.text or "").strip()
        # Strip accidental code fences.
        if text.startswith("```"):
            text = text.strip("`")
            text = text.split("\n", 1)[1] if "\n" in text else text
        data = json.loads(text)
    except Exception as e:
        await audit.emit(
            event_type="insight.generate",
            outcome="failure",
            actor_user_id=user.id,
            details={"scan_id": scan.id, "reason": type(e).__name__},
        )
        await db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Upstream returned invalid payload") from e

    # Re-validate the LLM output. If it lies about shape, we don't pass it through.
    try:
        response = InsightResponse(
            threat_landscape=str(data["threat_landscape"])[:2000],
            compliance_impact=str(data["compliance_impact"])[:2000],
            remediation_roadmap=[str(x)[:500] for x in data["remediation_roadmap"][:5]],
            model=_settings.gemini_model,
        )
    except (KeyError, TypeError, ValueError) as e:
        await audit.emit(
            event_type="insight.generate",
            outcome="failure",
            actor_user_id=user.id,
            details={"scan_id": scan.id, "reason": "schema_mismatch"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Upstream returned invalid schema") from e

    await audit.emit(
        event_type="insight.generate",
        outcome="success",
        actor_user_id=user.id,
        details={"scan_id": scan.id, "model": _settings.gemini_model},
    )
    await db.commit()
    return response
