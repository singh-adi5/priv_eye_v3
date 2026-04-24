"""Liveness + readiness probes."""

from fastapi import APIRouter

from ..ml.infer import current_model_version

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readiness() -> dict[str, str]:
    version = current_model_version()
    status = "ok" if version != "not-loaded" else "degraded"
    return {"status": status, "model_version": version}
