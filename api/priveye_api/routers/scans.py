"""
Scan ingest (agent) + scan history (user).

Ingest path is HMAC-authenticated and runs the ML model.
History path is JWT-authenticated and user-scoped.

Control refs:
- ASVS V2.6 — agent auth via HMAC
- ASVS V4.1.3 — user-scoped reads
- ASVS V7.2.1 / NIST AU-9 — soft-delete (tombstone)
"""


from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.audit import AuditLogger
from ..core.auth import get_agent_host, get_current_user
from ..core.db import get_db
from ..core.models import Host, Scan, User, generate_id
from ..ml import infer
from ..schemas import AnalysisResult, ScanRead, TelemetryPayload

router = APIRouter(prefix="/api/v1", tags=["scans"])


@router.post("/scans", response_model=AnalysisResult, status_code=201)
async def ingest_scan(
    payload: TelemetryPayload,
    request: Request,
    host: Annotated[Host, Depends(get_agent_host)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AnalysisResult:
    # Model is loaded at startup; if not, 503.
    try:
        result = infer.predict(payload.model_dump())
    except infer.ModelNotLoaded as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Model not loaded") from e
    except Exception as e:  # pragma: no cover — defensive
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Inference failed") from e

    scan = Scan(
        id=generate_id(),
        host_id=host.id,
        owner_id=host.owner_id,
        telemetry=payload.model_dump(),
        risk=result["risk"],
        score=result["score"],
        probabilities=result["probabilities"],
        feature_importances=result["feature_importances"],
        reasons=result["reasons"],
        model_version=result["model_version"],
    )
    db.add(scan)

    audit = AuditLogger(db)
    await audit.emit(
        event_type="scan.ingest",
        outcome="success",
        actor_user_id=host.owner_id,
        actor_ip=request.client.host if request.client else None,
        details={"host_id": host.id, "scan_id": scan.id, "risk": result["risk"]},
    )
    await db.commit()

    return AnalysisResult(**result)


@router.get("/scans", response_model=list[ScanRead])
async def list_scans(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    host_id: str | None = None,
    limit: int = 50,
) -> list[Scan]:
    if limit < 1 or limit > 200:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "limit must be 1..200")

    stmt = (
        select(Scan)
        .where(Scan.owner_id == user.id, Scan.deleted_at.is_(None))
        .order_by(Scan.created_at.desc())
        .limit(limit)
    )
    if host_id:
        stmt = stmt.where(Scan.host_id == host_id)

    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/scans/{scan_id}", response_model=ScanRead)
async def get_scan(
    scan_id: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Scan:
    scan = await db.get(Scan, scan_id)
    if scan is None or scan.owner_id != user.id or scan.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return scan


@router.delete("/scans/{scan_id}", status_code=204)
async def soft_delete_scan(
    scan_id: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Tombstone — preserves audit trail. Auditors retain visibility via /audit routes."""
    scan = await db.get(Scan, scan_id)
    if scan is None or scan.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    if scan.deleted_at is None:
        scan.deleted_at = datetime.now(timezone.utc)
    audit = AuditLogger(db)
    await audit.emit(
        event_type="scan.tombstone",
        outcome="success",
        actor_user_id=user.id,
        details={"scan_id": scan_id},
    )
    await db.commit()
