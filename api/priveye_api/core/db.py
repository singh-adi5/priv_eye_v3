"""
Async SQLAlchemy setup.

Control refs:
- ASVS V5.3.4 / NIST SI-10(5) — ORM only, no raw SQL
- ASVS V4.1.3 / NIST AC-4 — user_id scoping applied at query layer
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import datetime, timezone

from sqlalchemy import DateTime, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .config import get_settings


class Base(DeclarativeBase):
    """Declarative base with a shared UTC-aware timestamp mixin convention."""


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class IDMixin:
    """Use text IDs (ULID/UUID) so they're safe in URLs and predictable-length."""

    id: Mapped[str] = mapped_column(String(32), primary_key=True)


_settings = get_settings()
_engine = create_async_engine(
    _settings.database_url,
    echo=_settings.debug and _settings.environment == "development",
    future=True,
    pool_pre_ping=True,
)
_SessionLocal = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with _SessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create tables if they don't exist (dev convenience; use Alembic in prod)."""
    # Import models so they register on Base.metadata
    from . import models  # noqa: F401  pylint: disable=import-outside-toplevel

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
