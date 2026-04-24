"""Auth endpoint tests."""

from __future__ import annotations


def test_register_and_login(client) -> None:
    reg = client.post(
        "/api/v1/auth/register",
        json={"email": "user@example.com", "password": "StrongPassword123!"},
    )
    assert reg.status_code == 201
    assert reg.json()["email"] == "user@example.com"

    login = client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "StrongPassword123!"},
    )
    assert login.status_code == 200
    assert "access_token" in login.json()
    assert login.json()["token_type"] == "bearer"


def test_register_duplicate_returns_409(client) -> None:
    client.post(
        "/api/v1/auth/register",
        json={"email": "dup@example.com", "password": "StrongPassword123!"},
    )
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": "dup@example.com", "password": "StrongPassword123!"},
    )
    assert resp.status_code == 409


def test_login_wrong_password_returns_401(client) -> None:
    client.post(
        "/api/v1/auth/register",
        json={"email": "pw@example.com", "password": "StrongPassword123!"},
    )
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "pw@example.com", "password": "WrongPassword999!"},
    )
    assert resp.status_code == 401


def test_login_unknown_user_returns_401(client) -> None:
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "StrongPassword123!"},
    )
    assert resp.status_code == 401


def test_unauthenticated_request_returns_401(client) -> None:
    assert client.get("/api/v1/hosts").status_code == 401


def test_authenticated_request_returns_200(client) -> None:
    client.post(
        "/api/v1/auth/register",
        json={"email": "auth@example.com", "password": "StrongPassword123!"},
    )
    token = client.post(
        "/api/v1/auth/login",
        json={"email": "auth@example.com", "password": "StrongPassword123!"},
    ).json()["access_token"]
    resp = client.get("/api/v1/hosts", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
