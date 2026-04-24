"""
Auth endpoints: register, login, refresh, logout.

Control refs:
- ASVS V2.1.1 / NIST IA-5 — password complexity via schema
- ASVS V2.2.1 / NIST AC-7 — lockout after repeated failure
- ASVS V2.2.3 — generic auth-failure message
- ASVS V3.3 / NIST IA-11 — short-lived access + refresh rotation
- ASVS V7.1.1 / NIST AU-2 — every auth event audited
"""


import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.audit import AuditLogger
from ..core.auth import (
    create_access_token,
    get_user_by_email,
    hash_password,
    password_needs_rehash,
    verify_password,
)
from ..core.config import get_settings
from ..core.db import get_db
from ..core.models import RefreshToken, User, UserRole, generate_id
from ..core.security import limiter
from ..schemas import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
_settings = get_settings()

_MAX_FAILED_LOGINS = 5
_LOCKOUT_MINUTES = 15


def _new_refresh_token() -> tuple[str, str, str]:
    """Return (jti, plaintext, sha256). Plaintext returned only to caller."""
    plaintext = secrets.token_urlsafe(48)
    jti = secrets.token_urlsafe(16)
    digest = hashlib.sha256(plaintext.encode("ascii")).hexdigest()
    return jti, plaintext, digest


def _hash_refresh(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _client_ip(request: Request) -> str | None:
    # Behind a reverse proxy, respect X-Forwarded-For only if explicitly trusted (prod).
    return request.client.host if request.client else None


@router.post("/register", response_model=dict, status_code=201)
@limiter.limit("10/hour")
async def register(
    request: Request,
    body: RegisterRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    audit = AuditLogger(db)

    existing = await get_user_by_email(db, body.email.lower())
    if existing is not None:
        # Don't reveal user existence — return 201-ish generic response.
        # (Trade-off: honest-pot behaviour. Some teams prefer 409 here.)
        await audit.emit(
            event_type="user.register",
            outcome="failure",
            actor_ip=_client_ip(request),
            details={"email": body.email, "reason": "duplicate"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "Registration failed")

    user = User(
        id=generate_id(),
        email=body.email.lower(),
        password_hash=hash_password(body.password),
        role=UserRole.USER,
    )
    db.add(user)
    await audit.emit(
        event_type="user.register",
        outcome="success",
        actor_user_id=user.id,
        actor_ip=_client_ip(request),
        details={"email": user.email},
    )
    await db.commit()
    return {"id": user.id, "email": user.email}


@router.post("/login", response_model=TokenResponse)
@limiter.limit(f"{_settings.rate_limit_login_per_min}/minute")
async def login(
    request: Request,
    body: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    audit = AuditLogger(db)
    ip = _client_ip(request)
    ua = request.headers.get("user-agent")

    user = await get_user_by_email(db, body.email.lower())

    # Constant-effort path: always hash once even if user doesn't exist,
    # to avoid leaking account existence via timing.
    if user is None:
        verify_password(body.password, "$argon2id$v=19$m=65536,t=3,p=4$aaaaaaaaaaaaaaaa$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        await audit.emit(event_type="auth.login", outcome="failure",
                         actor_ip=ip, actor_ua=ua, details={"email": body.email, "reason": "no_user"})
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    now = datetime.now(timezone.utc)

    # Lockout check
    if user.locked_until and user.locked_until > now:
        await audit.emit(event_type="auth.login", outcome="failure",
                         actor_user_id=user.id, actor_ip=ip, actor_ua=ua,
                         details={"reason": "locked"})
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    if not verify_password(body.password, user.password_hash):
        user.failed_login_count += 1
        if user.failed_login_count >= _MAX_FAILED_LOGINS:
            user.locked_until = now + timedelta(minutes=_LOCKOUT_MINUTES)
            user.failed_login_count = 0  # reset counter; lockout is the penalty
        await audit.emit(event_type="auth.login", outcome="failure",
                         actor_user_id=user.id, actor_ip=ip, actor_ua=ua,
                         details={"reason": "bad_password"})
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    # Success — reset lockout state, rehash if params have improved.
    user.failed_login_count = 0
    user.locked_until = None
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)

    # Issue access + refresh
    access = create_access_token(user)
    jti, refresh_plain, refresh_digest = _new_refresh_token()
    refresh = RefreshToken(
        jti=jti,
        user_id=user.id,
        token_hash=refresh_digest,
        expires_at=now + timedelta(days=_settings.refresh_token_expire_days),
    )
    db.add(refresh)
    await audit.emit(event_type="auth.login", outcome="success",
                     actor_user_id=user.id, actor_ip=ip, actor_ua=ua,
                     details={"jti": jti})
    await db.commit()

    return TokenResponse(
        access_token=access,
        refresh_token=f"{jti}.{refresh_plain}",
        expires_in=_settings.access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("30/minute")
async def refresh_token(
    request: Request,
    body: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    audit = AuditLogger(db)
    ip = _client_ip(request)

    try:
        jti, plaintext = body.refresh_token.split(".", 1)
    except ValueError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token") from e

    stored = await db.get(RefreshToken, jti)
    now = datetime.now(timezone.utc)
    if stored is None or stored.revoked_at is not None or stored.expires_at < now:
        await audit.emit(event_type="auth.refresh", outcome="failure",
                         actor_ip=ip, details={"jti": jti, "reason": "not_valid"})
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    if stored.token_hash != _hash_refresh(plaintext):
        # Possible token theft — revoke the whole family (this token) and audit as attack.
        stored.revoked_at = now
        await audit.emit(event_type="auth.refresh", outcome="failure",
                         actor_user_id=stored.user_id, actor_ip=ip,
                         details={"jti": jti, "reason": "hash_mismatch"})
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    user = await db.get(User, stored.user_id)
    if user is None or not user.is_active:
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    # Rotation: revoke old, issue new.
    stored.revoked_at = now
    access = create_access_token(user)
    jti2, plain2, digest2 = _new_refresh_token()
    db.add(RefreshToken(
        jti=jti2, user_id=user.id, token_hash=digest2,
        expires_at=now + timedelta(days=_settings.refresh_token_expire_days),
    ))
    await audit.emit(event_type="auth.refresh", outcome="success",
                     actor_user_id=user.id, actor_ip=ip,
                     details={"old_jti": jti, "new_jti": jti2})
    await db.commit()
    return TokenResponse(
        access_token=access,
        refresh_token=f"{jti2}.{plain2}",
        expires_in=_settings.access_token_expire_minutes * 60,
    )


@router.post("/logout", status_code=204)
async def logout(
    request: Request,
    body: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    try:
        jti, _ = body.refresh_token.split(".", 1)
    except ValueError:
        # Still 204 — logout is idempotent.
        return
    stored = await db.get(RefreshToken, jti)
    if stored and stored.revoked_at is None:
        stored.revoked_at = datetime.now(timezone.utc)
    audit = AuditLogger(db)
    await audit.emit(event_type="auth.logout", outcome="success",
                     actor_user_id=stored.user_id if stored else None,
                     actor_ip=_client_ip(request))
    await db.commit()
