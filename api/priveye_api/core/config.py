"""
Typed application settings loaded from environment.

Control refs:
- ASVS V14.1.1 / NIST IA-5(7) — secrets only via env vars
- ASVS V1.1.5 / NIST CM-7 — secure defaults
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- App ---
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"

    # --- Auth ---
    jwt_secret: SecretStr = Field(..., min_length=32)
    jwt_algorithm: Literal["HS256", "RS256"] = "HS256"
    access_token_expire_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_expire_days: int = Field(default=14, ge=1, le=90)

    # Argon2id — OWASP 2023 recommended baseline
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost: int = Field(default=65536, ge=19456)  # >=19 MiB per OWASP
    argon2_parallelism: int = Field(default=4, ge=1)

    # --- DB ---
    database_url: str = "sqlite+aiosqlite:///./priveye.db"

    # --- Agent / HMAC ---
    agent_replay_window_seconds: int = Field(default=300, ge=30, le=900)
    agent_nonce_ttl_seconds: int = Field(default=600, ge=60, le=1800)

    # --- Rate limits ---
    rate_limit_login_per_min: int = Field(default=5, ge=1)
    rate_limit_api_per_min: int = Field(default=300, ge=1)
    rate_limit_scan_per_host_per_min: int = Field(default=60, ge=1)

    # --- ML ---
    model_path: str = "./priveye_api/ml/model.pkl"
    model_sha256: str = ""  # empty = skip verification (dev only; we log a warning)

    # --- Gemini (optional) ---
    gemini_api_key: SecretStr | None = None
    gemini_model: str = "gemini-1.5-flash"
    gemini_per_user_daily_quota: int = Field(default=30, ge=0)

    # --- CORS ---
    cors_origins: str = "http://localhost:3000,http://localhost:8000"

    @field_validator("cors_origins")
    @classmethod
    def _no_wildcard_in_prod(cls, v: str, info: Any) -> str:
        env = info.data.get("environment")
        if env == "production" and "*" in v:
            raise ValueError("CORS wildcard not allowed in production (ASVS V13.2.1)")
        return v

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def insights_enabled(self) -> bool:
        return self.gemini_api_key is not None and self.gemini_per_user_daily_quota > 0


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
