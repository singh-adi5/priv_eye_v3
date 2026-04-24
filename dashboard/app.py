"""
Priv-Eye dashboard server.

Thin Starlette app that:
1. Serves Jinja2-rendered HTML (login, dashboard).
2. Exposes /proxy/* — server-side relay to the FastAPI API so the browser
   never needs to know the API origin (avoids CORS in dev, mirrors prod proxy).

Run:
    pip install -r requirements.txt
    PRIVEYE_API=http://localhost:8000 uvicorn dashboard.app:app --port 3000 --reload

Control refs:
- ASVS V3.4.2 — HTTPOnly / SameSite cookies for session token storage
- ASVS V2.1 — login rate limiting delegated to API
"""

from __future__ import annotations

import os

import httpx
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_API_BASE = os.environ.get("PRIVEYE_API", "http://localhost:8000").rstrip("/")
_COOKIE_NAME = "pe_token"
_HERE = os.path.dirname(__file__)

_env = Environment(
    loader=FileSystemLoader(os.path.join(_HERE, "templates")),
    autoescape=select_autoescape(["html"]),
)


def _render(name: str, **ctx) -> HTMLResponse:  # type: ignore[no-untyped-def]
    return HTMLResponse(_env.get_template(name).render(**ctx))


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _token_from_request(request: Request) -> str | None:
    return request.cookies.get(_COOKIE_NAME)


def _set_token_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        _COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        secure=os.environ.get("ENVIRONMENT", "development") == "production",
        max_age=14 * 24 * 3600,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


async def homepage(request: Request) -> Response:
    if _token_from_request(request):
        return RedirectResponse("/dashboard", status_code=303)
    return RedirectResponse("/login", status_code=303)


async def login_page(request: Request) -> Response:
    if _token_from_request(request):
        return RedirectResponse("/dashboard", status_code=303)
    error = request.query_params.get("error", "")
    return _render("login.html", error=error, api_base=_API_BASE)


async def login_submit(request: Request) -> Response:
    form = await request.form()
    email = str(form.get("email", ""))
    password = str(form.get("password", ""))

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{_API_BASE}/api/v1/auth/login",
                json={"email": email, "password": password},
                timeout=10.0,
            )
        except httpx.HTTPError:
            return RedirectResponse("/login?error=Cannot+reach+API", status_code=303)

    if resp.status_code == 200:
        data = resp.json()
        redirect = RedirectResponse("/dashboard", status_code=303)
        _set_token_cookie(redirect, data["access_token"])
        return redirect

    if resp.status_code == 401:
        return RedirectResponse("/login?error=Invalid+credentials", status_code=303)
    return RedirectResponse("/login?error=Login+failed", status_code=303)


async def register_page(request: Request) -> Response:
    error = request.query_params.get("error", "")
    return _render("login.html", mode="register", error=error, api_base=_API_BASE)


async def register_submit(request: Request) -> Response:
    form = await request.form()
    email = str(form.get("email", ""))
    password = str(form.get("password", ""))

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{_API_BASE}/api/v1/auth/register",
                json={"email": email, "password": password},
                timeout=10.0,
            )
        except httpx.HTTPError:
            return RedirectResponse("/register?error=Cannot+reach+API", status_code=303)

    if resp.status_code == 201:
        # Auto-login after registration.
        async with httpx.AsyncClient() as client2:
            login_resp = await client2.post(
                f"{_API_BASE}/api/v1/auth/login",
                json={"email": email, "password": password},
                timeout=10.0,
            )
        if login_resp.status_code == 200:
            data = login_resp.json()
            redirect = RedirectResponse("/dashboard", status_code=303)
            _set_token_cookie(redirect, data["access_token"])
            return redirect

    msg = resp.json().get("detail", "Registration failed")
    return RedirectResponse(f"/register?error={msg}", status_code=303)


async def logout(request: Request) -> Response:
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(_COOKIE_NAME)
    return response


async def dashboard_page(request: Request) -> Response:
    token = _token_from_request(request)
    if not token:
        return RedirectResponse("/login", status_code=303)

    headers = {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient() as client:
        hosts_resp = await client.get(f"{_API_BASE}/api/v1/hosts", headers=headers, timeout=10.0)
        scans_resp = await client.get(f"{_API_BASE}/api/v1/scans?limit=20", headers=headers, timeout=10.0)
        health_resp = await client.get(f"{_API_BASE}/healthz", timeout=5.0)

    if hosts_resp.status_code == 401:
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(_COOKIE_NAME)
        return response

    hosts = hosts_resp.json() if hosts_resp.status_code == 200 else []
    scans = scans_resp.json() if scans_resp.status_code == 200 else []
    health = health_resp.json() if health_resp.status_code == 200 else {}

    return _render(
        "dashboard.html",
        hosts=hosts,
        scans=scans,
        health=health,
        api_base=_API_BASE,
    )


# ---------------------------------------------------------------------------
# API proxy (used by HTMX fragments for actions that need to talk to the API)
# ---------------------------------------------------------------------------


async def api_proxy(request: Request) -> Response:
    """Relay to the backend API with the user's cookie-based token."""
    token = _token_from_request(request)
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    path = request.path_params["path"]
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    body = await request.body()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.request(
                method=request.method,
                url=f"{_API_BASE}/api/v1/{path}",
                headers=headers,
                content=body or None,
                timeout=30.0,
            )
        except httpx.HTTPError as e:
            return JSONResponse({"detail": str(e)}, status_code=502)

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers={"Content-Type": resp.headers.get("content-type", "application/json")},
    )


# ---------------------------------------------------------------------------
# App assembly
# ---------------------------------------------------------------------------

routes = [
    Route("/", homepage),
    Route("/login", login_page, methods=["GET"]),
    Route("/login", login_submit, methods=["POST"]),
    Route("/register", register_page, methods=["GET"]),
    Route("/register", register_submit, methods=["POST"]),
    Route("/logout", logout, methods=["GET", "POST"]),
    Route("/dashboard", dashboard_page),
    Route("/proxy/{path:path}", api_proxy, methods=["GET", "POST", "DELETE"]),
    Mount("/static", StaticFiles(directory=os.path.join(_HERE, "static")), name="static"),
]

app = Starlette(routes=routes)
