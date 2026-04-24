"""
Model loading + inference.

Control refs:
- NIST AI RMF MANAGE-1.3 / SI-7(1) — artifact integrity verification
- ASVS V5.1.4 — input bounds before inference
- NIST AI RMF MAP-4.1 — model version recorded per prediction
"""

from __future__ import annotations

import hashlib
import logging
import threading
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from ..core.config import get_settings
from .features import FEATURE_COLUMNS, FeatureVector, build_feature_vector

_log = logging.getLogger("priveye.ml")
_settings = get_settings()

# Label order MUST match training (see scripts/train_model.py).
LABEL_ORDER: list[str] = ["LOW", "MEDIUM", "HIGH"]


class ModelNotLoadedError(RuntimeError):
    pass


ModelNotLoaded = ModelNotLoadedError  # backward-compat alias


class ModelIntegrityError(RuntimeError):
    """Raised when MODEL_SHA256 is configured but doesn't match the file on disk."""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_model_hash(path: Path) -> None:
    expected = _settings.model_sha256.strip()
    if not expected:
        if _settings.environment == "production":
            raise ModelIntegrityError("MODEL_SHA256 must be set in production")
        _log.warning("MODEL_SHA256 not set — skipping integrity check (dev only)")
        return
    actual = _sha256_file(path)
    if actual != expected:
        raise ModelIntegrityError(
            f"model.pkl SHA256 mismatch: expected={expected[:12]}… actual={actual[:12]}…"
        )


class _ModelHolder:
    """Thread-safe lazy loader. Loaded once at process startup via load_model()."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._model = None
        self._meta: dict[str, Any] = {}

    def load(self) -> None:
        with self._lock:
            if self._model is not None:
                return
            path = Path(_settings.model_path)
            if not path.exists():
                raise ModelNotLoadedError(
                    f"Model file not found at {path}. Run scripts/train_model.py first."
                )
            _verify_model_hash(path)
            payload = joblib.load(path)
            # payload = {"model": RF, "features": [...], "meta": {...}}
            self._model = payload["model"]
            declared_features = payload.get("features", [])
            if declared_features != FEATURE_COLUMNS:
                raise ModelNotLoadedError(
                    "Feature list in model.pkl does not match FEATURE_COLUMNS. "
                    "Retrain after changing feature set."
                )
            self._meta = payload.get("meta", {})
            _log.info(
                "Model loaded: version=%s sha=%s",
                self._meta.get("version"),
                self._meta.get("sha256", "")[:12],
            )

    @property
    def model(self):  # type: ignore[no-untyped-def]
        if self._model is None:
            raise ModelNotLoadedError("Model not loaded — call load_model() at startup")
        return self._model

    @property
    def version(self) -> str:
        return str(self._meta.get("version", "unknown"))

    @property
    def feature_importances(self) -> dict[str, float]:
        importances = getattr(self.model, "feature_importances_", None)
        if importances is None:
            return {}
        return {col: float(v) for col, v in zip(FEATURE_COLUMNS, importances, strict=False)}


_holder = _ModelHolder()


def load_model() -> None:
    """Call once at app startup. Safe to call again — no-op if already loaded."""
    _holder.load()


def _validate_features(values: list[float]) -> None:
    """
    Defensive bounds check. Pydantic already enforced upstream, but the model
    inference path must not trust that in case this is called programmatically.
    """
    if len(values) != len(FEATURE_COLUMNS):
        raise ValueError("feature vector length mismatch")
    for v in values:
        if not np.isfinite(v):
            raise ValueError("non-finite feature value")
        if v < 0 or v > 100_000:
            raise ValueError("feature value out of bounds")


def _derive_reasons(features: dict[str, float]) -> list[str]:
    """Human-readable bullet list — independent of the ML score, drawn from the telemetry itself."""
    r: list[str] = []
    if features.get("sudo_has_nopasswd"):
        r.append("NOPASSWD sudo rule detected")
    if features.get("sudo_has_all"):
        r.append("Over-permissive sudo rule (ALL:ALL)")
    if features.get("suid_total_count", 0) > 40:
        r.append("Excessive SUID binary count")
    if features.get("kernel_major", 0) < 5:
        r.append("Kernel major version below maintained line")
    if features.get("suid_pkexec"):
        r.append("pkexec present — verify patched against CVE-2021-4034")
    return r


def predict(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Score a validated telemetry payload. Returns a dict compatible with
    `schemas.AnalysisResult`.
    """
    fv: FeatureVector = build_feature_vector(
        kernel_version=payload["kernel_version"],
        suid_binaries=payload.get("suid_binaries", []),
        sudo_privileges=payload.get("sudo_privileges", ""),
        euid=payload.get("euid", 1000),
    )
    _validate_features(fv.values)

    # Use a named DataFrame so sklearn doesn't warn about missing feature names.
    features = pd.DataFrame([fv.values], columns=FEATURE_COLUMNS)
    probas = _holder.model.predict_proba(features)[0]  # shape (3,)
    # sklearn returns probas aligned with .classes_; we trained with 0=LOW,1=MEDIUM,2=HIGH
    classes = list(getattr(_holder.model, "classes_", [0, 1, 2]))
    # Reorder to our canonical LOW, MEDIUM, HIGH
    prob_map = {LABEL_ORDER[int(c)]: float(p) for c, p in zip(classes, probas, strict=False)}
    # Safety if classes_ didn't include all 3 (shouldn't happen with stratified train)
    for lvl in LABEL_ORDER:
        prob_map.setdefault(lvl, 0.0)

    pred_idx = int(np.argmax(probas))
    risk = LABEL_ORDER[classes[pred_idx]]
    score = int(round(prob_map["MEDIUM"] * 50 + prob_map["HIGH"] * 100))

    return {
        "risk": risk,
        "score": max(0, min(100, score)),
        "probabilities": prob_map,
        "feature_importances": _holder.feature_importances,
        "reasons": _derive_reasons(fv.humanized),
        "model_version": _holder.version,
    }


def current_model_version() -> str:
    try:
        return _holder.version
    except ModelNotLoadedError:
        return "not-loaded"


__all__ = [
    "ModelIntegrityError",
    "ModelNotLoadedError",
    "current_model_version",
    "load_model",
    "predict",
]
