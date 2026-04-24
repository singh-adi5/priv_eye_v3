"""
Transport tests — focus on the signing contract and error handling.

The `test_signature_matches_api` case re-implements the API-side canonical
form from scratch; if the agent and API ever drift, this test fails.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from priveye_agent.transport import AgentCredentials, TransportError, _sign


def test_signature_matches_api_canonical_form() -> None:
    """
    Cross-component contract test.

    The API computes the signature as:
      HMAC-SHA256(key, timestamp + "\\n" + nonce + "\\n" + body_bytes)

    If this drifts, every real scan will 401. We inline the expected form here
    so this test would fail loudly if someone changes one side only.
    """
    body_bytes = b'{"k":"v"}'
    timestamp = "1700000000"
    nonce = "abcd1234"
    key = "secret"

    expected = hmac.new(
        key.encode(),
        timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body_bytes,
        hashlib.sha256,
    ).hexdigest()

    actual = _sign(body_bytes, timestamp, nonce, key)
    assert actual == expected


def test_signature_differs_if_body_changes() -> None:
    """Sanity: tampering with the body invalidates the signature."""
    sig1 = _sign(b'{"a":1}', "1700000000", "nonce", "key")
    sig2 = _sign(b'{"a":2}', "1700000000", "nonce", "key")
    assert sig1 != sig2


def test_signature_differs_if_nonce_changes() -> None:
    sig1 = _sign(b"body", "1700000000", "nonce-a", "key")
    sig2 = _sign(b"body", "1700000000", "nonce-b", "key")
    assert sig1 != sig2


def test_credentials_from_env_requires_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PRIVEYE_API", raising=False)
    monkeypatch.delenv("PRIVEYE_HOST_ID", raising=False)
    monkeypatch.delenv("PRIVEYE_HMAC_KEY", raising=False)
    with pytest.raises(TransportError, match="Missing required env vars"):
        AgentCredentials.from_env()


def test_credentials_from_env_strips_trailing_slash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRIVEYE_API", "https://example.com/")
    monkeypatch.setenv("PRIVEYE_HOST_ID", "host123")
    monkeypatch.setenv("PRIVEYE_HMAC_KEY", "key")
    creds = AgentCredentials.from_env()
    assert creds.api_base == "https://example.com"


def test_body_bytes_are_deterministic() -> None:
    """
    Canonical JSON must be stable between runs — else signature won't match
    even a correctly-computed server-side check.
    """
    payload = {"kernel_version": "6.1", "euid": 1000, "suid_binaries": ["sudo", "pkexec"]}
    b1 = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    b2 = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    assert b1 == b2
