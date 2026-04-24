"""
Host registration and management.

Control refs:
- ASVS V4.1.3 / NIST AC-4 — queries scoped to current user
- Per-host HMAC key issued once at creation; stored hashed.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.audit import AuditLogger
from ..core.auth import generate_hmac_key, get_current_user, hash_hmac_key
from ..core.db import get_db
from ..core.models import Host, User, generate_id
from ..schemas import HostCreate, HostCreateResponse, HostRead

router = APIRouter(prefix="/api/v1/hosts", tags=["hosts"])


@router.post("", response_model=HostCreateResponse, status_code=201)
async def create_host(
    body: HostCreate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> HostCreateResponse:
    # Hostname uniqueness scoped to user, not global.
    existing = await db.execute(
        select(Host).where(Host.owner_id == user.id, Host.hostname == body.hostname)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Host with this name already registered")

    key = generate_hmac_key()
    host = Host(
        id=generate_id(),
        owner_id=user.id,
        hostname=body.hostname,
        environment=body.environment,
        hmac_key_hash=hash_hmac_key(key),
        is_active=True,
    )
    db.add(host)

    audit = AuditLogger(db)
    await audit.emit(
        event_type="host.create",
        outcome="success",
        actor_user_id=user.id,
        details={"host_id": host.id, "hostname": host.hostname},
    )
    await db.commit()
    await db.refresh(host)

    return HostCreateResponse(
        id=host.id,
        hostname=host.hostname,
        environment=host.environment,
        is_active=host.is_active,
        created_at=host.created_at,
        hmac_key=key,  # shown ONCE — user must store it on the target host
    )


@router.get("", response_model=list[HostRead])
async def list_hosts(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[Host]:
    result = await db.execute(
        select(Host).where(Host.owner_id == user.id).order_by(Host.created_at.desc())
    )
    return list(result.scalars().all())


@router.delete("/{host_id}", status_code=204)
async def delete_host(
    host_id: str,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    host = await db.get(Host, host_id)
    if host is None or host.owner_id != user.id:
        # Don't reveal whether the ID exists but isn't ours.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    host.is_active = False
    audit = AuditLogger(db)
    await audit.emit(
        event_type="host.deactivate",
        outcome="success",
        actor_user_id=user.id,
        details={"host_id": host.id},
    )
    await db.commit()
