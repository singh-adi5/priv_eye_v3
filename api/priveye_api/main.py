"""
FastAPI application factory.

Lifecycle:
1. On startup: load Settings, init DB (dev), load ML model.
2. On shutdown: close DB.

Control refs:
- ASVS V7.4 — no stack traces to clients
- ASVS V14.1 — debug off by default in prod
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import __version__
from .core.config import get_settings
from .core.db import init_db
from .core.security import configure_app_security
from .ml.infer import ModelIntegrityError, ModelNotLoadedError, load_model
from .routers import auth, health, hosts, insights, scans

_log = logging.getLogger("priveye")


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    settings = get_settings()
    _configure_logging(settings.log_level)
    _log.info("Starting Priv-Eye API v%s (env=%s)", __version__, settings.environment)

    # Dev convenience — in prod, Alembic owns schema.
    if settings.environment == "development":
        await init_db()

    try:
        load_model()
    except (ModelNotLoadedError, ModelIntegrityError) as e:
        if settings.environment == "production":
            raise
        _log.warning("Model not available: %s — API will return 503 on /scans", e)

    yield
    _log.info("Shutting down Priv-Eye API")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Priv-Eye API",
        version=__version__,
        docs_url="/docs" if settings.debug else None,  # hide in prod
        redoc_url=None,
        openapi_url="/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )

    configure_app_security(app)

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(hosts.router)
    app.include_router(scans.router)
    app.include_router(insights.router)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # ASVS V7.4 — no internals leak. Log the real thing server-side.
        _log.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return app


app = create_app()
