"""
Transport-layer hardening: security headers, rate limiting, CORS.

Control refs:
- ASVS V14.4 / NIST SC-18 — security headers
- ASVS V13.1 / NIST SC-5 — rate limiting
- ASVS V13.2.1 / NIST SC-7 — CORS allowlist
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from .config import get_settings

_settings = get_settings()


# Rate limiter keyed on client IP. For login + agent endpoints we layer
# finer-grained limits at the endpoint (per-user, per-host).
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{_settings.rate_limit_api_per_min}/minute"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Applies a strict default set of headers on every response.
    CSP is intentionally restrictive for the JSON API; the dashboard
    relaxes it per-route when it serves HTML.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)

        # Core set
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        # Default CSP for API responses — no scripts, no embeds.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'",
        )
        # HSTS only in prod (dev often uses plain HTTP on localhost).
        if _settings.environment == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        return response


def configure_app_security(app: FastAPI) -> None:
    """Attach middleware + CORS + rate-limit error handler."""
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "PATCH"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-PrivEye-Host",
            "X-PrivEye-Signature",
            "X-PrivEye-Timestamp",
            "X-PrivEye-Nonce",
            "X-PrivEye-Key",
        ],
        max_age=600,
    )

    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
        # Minimal body; don't echo headers that could leak the limit policy.
        return Response(
            content='{"detail":"Rate limit exceeded"}',
            status_code=429,
            media_type="application/json",
        )
