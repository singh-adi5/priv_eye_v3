"""
SQLAlchemy ORM models.

Key design calls:
- Scans are soft-deleted (tombstoned) to preserve audit trail — ASVS V7.2.1 / NIST AU-9.
- HMAC keys are stored as Argon2id digests so a DB leak doesn't yield usable keys.
- `model_version` on every scan — NIST AI RMF MAP-4.1.
"""

from __future__ import annotations

import enum
import secrets
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, IDMixin, TimestampMixin


def _new_id(n: int = 16) -> str:
    """16 bytes of CSPRNG → 32 hex chars. Collision-safe for this scale."""
    return secrets.token_hex(n)


class UserRole(str, enum.Enum):
    USER = "user"
    AUDITOR = "auditor"
    ADMIN = "admin"


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class User(Base, IDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, native_enum=False), default=UserRole.USER, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    hosts: Mapped[list[Host]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class Host(Base, IDMixin, TimestampMixin):
    __tablename__ = "hosts"

    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)  # RFC 1035 max
    environment: Mapped[str] = mapped_column(String(32), default="default", nullable=False)
    # HMAC key stored hashed — we only need to verify the agent presents the right one.
    hmac_key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    owner: Mapped[User] = relationship(back_populates="hosts")
    scans: Mapped[list[Scan]] = relationship(back_populates="host", cascade="all, delete-orphan")


class Scan(Base, IDMixin, TimestampMixin):
    __tablename__ = "scans"

    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)

    # The raw (validated) feature vector used at inference time. JSON for flexibility;
    # values are bounded by Pydantic upstream so no unbounded-size risk.
    telemetry: Mapped[dict] = mapped_column(JSON, nullable=False)

    # Output of the RF
    risk: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel, native_enum=False), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0..100
    probabilities: Mapped[dict] = mapped_column(JSON, nullable=False)  # {LOW, MEDIUM, HIGH}
    feature_importances: Mapped[dict] = mapped_column(JSON, nullable=False)
    reasons: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    model_version: Mapped[str] = mapped_column(String(64), nullable=False)

    # Tombstoning (ASVS V7.2.1 / NIST AU-9): DELETE sets deleted_at, never removes row.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    host: Mapped[Host] = relationship(back_populates="scans")


class AuditLog(Base, IDMixin, TimestampMixin):
    """
    Append-only audit log. DELETEs on this table are not allowed at the app layer
    (would require direct DB access, which is out of the app container's trust zone).

    NIST AU-2, AU-3, AU-9.
    """

    __tablename__ = "audit_log"

    actor_user_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    actor_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_ua: Mapped[str | None] = mapped_column(String(512), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)  # success | failure
    # Redacted payload (no passwords, no tokens, no HMAC keys) — see core/audit.py
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class RefreshToken(Base, TimestampMixin):
    """
    Opaque refresh tokens stored hashed. Rotation on use; revocation on logout.
    ASVS V3.3 / NIST IA-11.
    """

    __tablename__ = "refresh_tokens"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Nonce(Base):
    """
    Seen-nonce cache for agent HMAC replay protection.
    Rows older than `AGENT_NONCE_TTL_SECONDS` are swept by a background task.
    """

    __tablename__ = "agent_nonces"

    nonce: Mapped[str] = mapped_column(String(128), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


def generate_id() -> str:
    """Public helper for routers that need to mint a new row ID."""
    return _new_id()
