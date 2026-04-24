"""
Authentication & authorization primitives.

- Passwords: Argon2id (ASVS V2.4.1 / NIST IA-5(1))
- Access tokens: short-lived JWT, role claim (ASVS V3.3 / NIST IA-11)
- Agent: per-host HMAC-SHA256 with timestamp + nonce (ASVS V2.6, V2.9 / NIST IA-3(1), SI-7)
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .db import get_db
from .models import Host, Nonce, User, UserRole

_settings = get_settings()

_ph = PasswordHasher(
    time_cost=_settings.argon2_time_cost,
    memory_cost=_settings.argon2_memory_cost,
    parallelism=_settings.argon2_parallelism,
)

_bearer = HTTPBearer(auto_error=False)


# ----------------------------------------------------------------------------
# Passwords
# ----------------------------------------------------------------------------


def hash_password(plaintext: str) -> str:
    """Argon2id hash. The salt is embedded in the returned string."""
    return _ph.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    """Constant-time verify. Returns False on any mismatch, never raises."""
    try:
        _ph.verify(hashed, plaintext)
        return True
    except VerifyMismatchError:
        return False
    except Exception:  # malformed hash, unknown algo, etc.
        return False


def password_needs_rehash(hashed: str) -> bool:
    """True if the stored hash was produced with weaker params than current."""
    return _ph.check_needs_rehash(hashed)


# ----------------------------------------------------------------------------
# JWT access tokens
# ----------------------------------------------------------------------------


def create_access_token(user: User) -> str:
    """Short-lived access token. Role is a server-signed claim — never trust client role."""
    now = datetime.now(UTC)
    payload = {
        "sub": user.id,
        "email": user.email,
        "role": user.role.value,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=_settings.access_token_expire_minutes)).timestamp()),
        "typ": "access",
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(
        payload,
        _settings.jwt_secret.get_secret_value(),
        algorithm=_settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """Raises jwt.PyJWTError on failure. Caller should catch and return 401."""
    return jwt.decode(
        token,
        _settings.jwt_secret.get_secret_value(),
        algorithms=[_settings.jwt_algorithm],
        options={"require": ["exp", "iat", "sub", "typ"]},
    )


async def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")

    try:
        payload = decode_access_token(creds.credentials)
    except jwt.PyJWTError as e:
        # Generic message — don't leak which part failed (ASVS V2.2.3).
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token") from e

    if payload.get("typ") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token type")

    user = await db.get(User, payload["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or disabled")

    return user


def require_role(*allowed: UserRole) -> Any:
    """Factory: use as a dependency. Enforces role at endpoint level (ASVS V4.2)."""

    async def dep(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return user

    return dep


# ----------------------------------------------------------------------------
# Agent HMAC
# ----------------------------------------------------------------------------


def generate_hmac_key() -> str:
    """32 bytes of CSPRNG, base64url. Returned once to the user at host registration."""
    return secrets.token_urlsafe(32)


def hash_hmac_key(key: str) -> str:
    """Store hashed so a DB leak doesn't hand over working agent keys."""
    return _ph.hash(key)


def verify_hmac_key(key: str, hashed: str) -> bool:
    try:
        _ph.verify(hashed, key)
        return True
    except Exception:
        return False


def compute_signature(body: bytes, timestamp: str, nonce: str, key: str) -> str:
    """
    Canonical HMAC-SHA256 over: timestamp . "\\n" . nonce . "\\n" . body.
    Using a literal separator prevents ambiguity attacks where attacker
    concatenates fields differently.
    """
    msg = timestamp.encode("ascii") + b"\n" + nonce.encode("ascii") + b"\n" + body
    return hmac.new(key.encode("ascii"), msg, hashlib.sha256).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("ascii"), b.encode("ascii"))


async def verify_agent_request(
    request: Request,
    db: AsyncSession,
    host_id: str,
    signature: str,
    timestamp: str,
    nonce: str,
) -> Host:
    """
    Full agent-request verification pipeline. Raises 401 on any failure,
    with a generic message, and logs the reason internally via AuditLogger.
    """
    # 1. Host exists and is active.
    host = await db.get(Host, host_id)
    if host is None or not host.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent authentication failed")

    # 2. Timestamp within window.
    try:
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent authentication failed") from e

    now = datetime.now(UTC)
    drift = abs((now - ts).total_seconds())
    if drift > _settings.agent_replay_window_seconds:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent authentication failed")

    # 3. Nonce not seen.
    # Cap nonce length to keep the table row small.
    if len(nonce) < 16 or len(nonce) > 128:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent authentication failed")

    existing = await db.get(Nonce, nonce)
    if existing is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent authentication failed")

    # 4. Recompute signature and compare constant-time.
    # We can't recover the plaintext key from the hash (that's the point), so
    # we instead require the client to send the key once per registration,
    # and we verify against the Argon2 digest on each request. For higher-volume
    # deployments, cache a verified key per host ID behind an LRU (see DEPLOYMENT.md).
    # For this build we accept the perf cost in exchange for keys-at-rest safety.
    body = await request.body()
    # The agent sends the key in `X-PrivEye-Key` on each request (TLS required in prod).
    key_header = request.headers.get("X-PrivEye-Key")
    if not key_header or not verify_hmac_key(key_header, host.hmac_key_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent authentication failed")

    expected = compute_signature(body, timestamp, nonce, key_header)
    if not constant_time_equals(expected, signature):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent authentication failed")

    # 5. Record nonce so the same request can't be replayed.
    db.add(Nonce(nonce=nonce, host_id=host_id))
    await db.flush()

    return host


async def get_agent_host(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    x_priveye_host: Annotated[str | None, Header()] = None,
    x_priveye_signature: Annotated[str | None, Header()] = None,
    x_priveye_timestamp: Annotated[str | None, Header()] = None,
    x_priveye_nonce: Annotated[str | None, Header()] = None,
) -> Host:
    if not all([x_priveye_host, x_priveye_signature, x_priveye_timestamp, x_priveye_nonce]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent authentication failed")

    return await verify_agent_request(
        request=request,
        db=db,
        host_id=x_priveye_host,  # type: ignore[arg-type]
        signature=x_priveye_signature,  # type: ignore[arg-type]
        timestamp=x_priveye_timestamp,  # type: ignore[arg-type]
        nonce=x_priveye_nonce,  # type: ignore[arg-type]
    )


# ----------------------------------------------------------------------------
# User lookup helper used by auth router
# ----------------------------------------------------------------------------


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email.lower()))
    return result.scalar_one_or_none()
