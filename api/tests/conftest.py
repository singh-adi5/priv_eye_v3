"""
Test configuration.

Uses asyncio.run() (not deprecated get_event_loop) and function-scoped
fixtures so each test gets a fresh DB — no cross-test contamination.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Must be set before any priveye_api import triggers pydantic Settings
os.environ.setdefault("JWT_SECRET", "ci-test-secret-not-real-at-least-32-chars")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
os.environ.setdefault("MODEL_PATH", "priveye_api/ml/model.pkl")

from priveye_api.core.db import Base, get_db  # noqa: E402
from priveye_api.main import create_app  # noqa: E402


def _make_engine():
    return create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
    )


def _init_db(engine):
    async def _run():
        from priveye_api.core import models  # noqa: F401 — registers ORM models

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_run())


@pytest.fixture()
def client():
    engine = _make_engine()
    _init_db(engine)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def _override_get_db():  # type: ignore[return]
        async with session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    app = create_app()
    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
