"""
Pydantic request/response schemas.

These enforce ASVS V5.1 (validation), V5.1.4 (ranges), and are the single
source of truth for what the API accepts. Everything downstream can assume
bounded, well-typed input.
"""

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator

from .core.models import RiskLevel, UserRole

# ----------------------------------------------------------------------------
# Reusable constrained primitives
# ----------------------------------------------------------------------------

Hostname = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=253,
        # RFC 1035-ish — letters, digits, dots, hyphens. Rejects shell metacharacters,
        # which matters because hostname ends up in generated remediation commands.
        pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$",
    ),
]

SafeString = Annotated[str, StringConstraints(min_length=1, max_length=256, strip_whitespace=True)]
EnvironmentName = Annotated[
    str, StringConstraints(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_-]{0,31}$")
]
StrongPassword = Annotated[str, StringConstraints(min_length=12, max_length=128)]

# ----------------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    email: EmailStr
    password: StrongPassword

    @field_validator("password")
    @classmethod
    def _policy(cls, v: str) -> str:
        # Minimal policy consistent with NIST SP 800-63B: length + variety hint,
        # no composition rules that frustrate users.
        if v.lower() in {"password123456", "adminadminadmin"}:
            raise ValueError("password is in common-password list")
        if len(set(v)) < 6:
            raise ValueError("password lacks variety")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: Annotated[str, StringConstraints(min_length=1, max_length=128)]


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: Annotated[str, StringConstraints(min_length=16, max_length=1024)]


# ----------------------------------------------------------------------------
# Hosts
# ----------------------------------------------------------------------------


class HostCreate(BaseModel):
    hostname: Hostname
    environment: EnvironmentName = "default"


class HostRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    hostname: str
    environment: str
    is_active: bool
    created_at: datetime


class HostCreateResponse(HostRead):
    """Returned once at creation time — `hmac_key` is never shown again."""

    hmac_key: str


# ----------------------------------------------------------------------------
# Telemetry (agent → API)
# ----------------------------------------------------------------------------


class TelemetryPayload(BaseModel):
    """
    What the agent sends. Matches v1's feature surface but adds explicit bounds
    so a crafted payload can't cause algorithmic DoS inside the ML path
    (ASVS V5.1.4, V11.1.6 / NIST SI-10).
    """

    model_config = ConfigDict(extra="forbid")

    kernel_version: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    suid_binaries: list[Annotated[str, StringConstraints(min_length=1, max_length=512)]] = Field(
        default_factory=list, max_length=2000
    )
    sudo_privileges: Annotated[str, StringConstraints(max_length=16_384)] = ""
    euid: Annotated[int, Field(ge=0, le=65535)] = 1000

    @field_validator("kernel_version")
    @classmethod
    def _kernel_format(cls, v: str) -> str:
        # Loose but bounded: digits, dots, letters, hyphens, plus-signs.
        if not re.fullmatch(r"[0-9a-zA-Z\.\-\+_]{1,64}", v):
            raise ValueError("kernel_version format invalid")
        return v


class AnalysisResult(BaseModel):
    risk: RiskLevel
    score: Annotated[int, Field(ge=0, le=100)]
    probabilities: dict[Literal["LOW", "MEDIUM", "HIGH"], float]
    feature_importances: dict[str, float]
    reasons: list[SafeString]
    model_version: str


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    host_id: str
    risk: RiskLevel
    score: int
    probabilities: dict[str, float]
    reasons: list[str]
    model_version: str
    created_at: datetime


# ----------------------------------------------------------------------------
# Insights (Gemini)
# ----------------------------------------------------------------------------


class InsightRequest(BaseModel):
    scan_id: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]


class InsightResponse(BaseModel):
    threat_landscape: str
    compliance_impact: str
    remediation_roadmap: list[str]
    model: str  # which LLM produced it


# ----------------------------------------------------------------------------
# Admin / role management
# ----------------------------------------------------------------------------


class RoleChangeRequest(BaseModel):
    user_id: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]
    role: UserRole
