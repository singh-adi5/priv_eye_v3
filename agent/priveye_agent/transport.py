"""
HMAC-signed telemetry upload.

Canonical signing string MUST match the API's `compute_signature` byte-for-byte:

    timestamp + "\n" + nonce + "\n" + body_bytes

If this ever drifts, every scan 401s. The alignment is verified by the
cross-component test `tests/test_transport.py::test_signature_matches_api`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

import httpx

_log = logging.getLogger("priveye.agent.transport")


class TransportError(Exception):
    """Unified error for upload failures."""


@dataclass(frozen=True)
class AgentCredentials:
    api_base: str
    host_id: str
    hmac_key: str

    @classmethod
    def from_env(cls) -> AgentCredentials:
        missing = [
            name
            for name in ("PRIVEYE_API", "PRIVEYE_HOST_ID", "PRIVEYE_HMAC_KEY")
            if not os.environ.get(name)
        ]
        if missing:
            raise TransportError(f"Missing required env vars: {', '.join(missing)}")
        return cls(
            api_base=os.environ["PRIVEYE_API"].rstrip("/"),
            host_id=os.environ["PRIVEYE_HOST_ID"],
            hmac_key=os.environ["PRIVEYE_HMAC_KEY"],
        )


def _sign(body_bytes: bytes, timestamp: str, nonce: str, key: str) -> str:
    canonical = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body_bytes
    return hmac.new(key.encode(), canonical, hashlib.sha256).hexdigest()


def upload_scan(
    payload: dict[str, Any],
    creds: AgentCredentials,
    *,
    verify_tls: bool = True,
    timeout_s: float = 30.0,
) -> dict[str, Any]:
    """
    POST a telemetry payload to /api/v1/scans.

    Returns the parsed JSON analysis result on success.
    Raises TransportError on any failure (network, auth, schema, etc.).
    """
    url = f"{creds.api_base}/api/v1/scans"
    # Canonical JSON — must be byte-identical to what we sign.
    body_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    signature = _sign(body_bytes, timestamp, nonce, creds.hmac_key)

    headers = {
        "Content-Type": "application/json",
        "X-PrivEye-Host": creds.host_id,
        "X-PrivEye-Key": creds.hmac_key,
        "X-PrivEye-Timestamp": timestamp,
        "X-PrivEye-Nonce": nonce,
        "X-PrivEye-Signature": signature,
        "User-Agent": "priveye-agent/0.3.0",
    }

    if not verify_tls:
        _log.warning("TLS verification DISABLED — use only for self-signed lab setups")

    try:
        resp = httpx.post(
            url,
            content=body_bytes,
            headers=headers,
            timeout=timeout_s,
            verify=verify_tls,
        )
    except httpx.HTTPError as e:
        raise TransportError(f"network error: {e}") from e

    if resp.status_code == 401:
        raise TransportError("auth rejected (401) — check host id, key, and clock skew")
    if resp.status_code == 409:
        raise TransportError("nonce already used (409) — replay protection triggered")
    if resp.status_code == 429:
        raise TransportError("rate limited (429) — back off and retry")
    if resp.status_code >= 500:
        raise TransportError(f"server error {resp.status_code} — see server logs")
    if resp.status_code != 201:
        raise TransportError(f"unexpected status {resp.status_code}: {resp.text[:200]}")

    try:
        return resp.json()
    except ValueError as e:
        raise TransportError("server returned non-JSON body") from e
