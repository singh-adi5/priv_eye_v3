"""
Training script — ported from v1's `train_model.py`, tightened.

What we keep from v1:
- scikit-learn RandomForestClassifier, 300 trees, max_depth=7
- 3-class synthetic distribution (low / medium / high)
- class_weight="balanced"
- stratified train/test split

What we add:
- Deterministic seed → hashable params for reproducibility
- model_meta.json written alongside model.pkl (version, sha256, trained_at, params, accuracy)
- Feature set locked to `features.FEATURE_COLUMNS` (must not drift)
- No ambient globals — everything passes through a function signature so CI can import and invoke

Run: `python -m priveye_api.ml.train`
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from ..core.config import get_settings
from .features import FEATURE_COLUMNS, KNOWN_FLAVORS

_log = logging.getLogger("priveye.ml.train")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MODEL_VERSION = "0.1.0"
RNG_SEED = 42


def synthesize(n: int = 1500, seed: int = RNG_SEED) -> pd.DataFrame:
    """
    Synthetic 3-class distribution mirroring v1 but aligned to the current
    feature set (kernel flavor one-hots instead of a categorical column).
    """
    rng = np.random.default_rng(seed)
    per = n // 3

    def _block(
        label: int,
        kernel_major_range: tuple[int, int],
        kernel_minor_range: tuple[int, int],
        flavor_probs: dict[str, float],
        pkexec_p: float,
        mount_p: float,
        chsh_p: float,
        suid_total_range: tuple[int, int],
        sudo_all_p: float,
        sudo_nopasswd_p: float,
        count: int,
    ) -> pd.DataFrame:
        flavors = list(flavor_probs.keys())
        weights = np.array(list(flavor_probs.values()), dtype=float)
        weights /= weights.sum()
        picked = rng.choice(flavors, size=count, p=weights)
        df = pd.DataFrame(
            {
                "kernel_major": rng.integers(*kernel_major_range, size=count),
                "kernel_minor": rng.integers(*kernel_minor_range, size=count),
                "kernel_patch": rng.integers(0, 12, size=count),
                "suid_pkexec": rng.choice([0, 1], size=count, p=[1 - pkexec_p, pkexec_p]),
                "suid_su": np.ones(count, dtype=int),
                "suid_sudo": np.ones(count, dtype=int),
                "suid_mount": rng.choice([0, 1], size=count, p=[1 - mount_p, mount_p]),
                "suid_passwd": np.ones(count, dtype=int),
                "suid_chsh": rng.choice([0, 1], size=count, p=[1 - chsh_p, chsh_p]),
                "suid_total_count": rng.integers(*suid_total_range, size=count),
                "sudo_has_all": rng.choice([0, 1], size=count, p=[1 - sudo_all_p, sudo_all_p]),
                "sudo_has_nopasswd": rng.choice(
                    [0, 1], size=count, p=[1 - sudo_nopasswd_p, sudo_nopasswd_p]
                ),
                "euid_is_root": np.zeros(count, dtype=int),
                "risk_label": np.full(count, label, dtype=int),
            }
        )
        for f in KNOWN_FLAVORS:
            df[f"kernel_flavor_{f}"] = (picked == f).astype(int)
        df["kernel_flavor_unknown"] = 0
        return df

    low = _block(
        label=0,
        kernel_major_range=(5, 7),
        kernel_minor_range=(12, 24),
        flavor_probs={"ubuntu": 0.4, "rhel": 0.4, "standard": 0.2},
        pkexec_p=0.02,
        mount_p=0.8,
        chsh_p=0.2,
        suid_total_range=(10, 22),
        sudo_all_p=0.03,
        sudo_nopasswd_p=0.01,
        count=per,
    )
    med = _block(
        label=1,
        kernel_major_range=(5, 7),
        kernel_minor_range=(8, 22),
        flavor_probs={"ubuntu": 0.5, "debian": 0.3, "standard": 0.2},
        pkexec_p=0.15,
        mount_p=1.0,
        chsh_p=0.5,
        suid_total_range=(18, 35),
        sudo_all_p=0.3,
        sudo_nopasswd_p=0.1,
        count=per,
    )
    high = _block(
        label=2,
        kernel_major_range=(4, 7),
        kernel_minor_range=(0, 18),
        flavor_probs={"kali-amd64": 0.5, "debian": 0.3, "standard": 0.2},
        pkexec_p=0.75,
        mount_p=1.0,
        chsh_p=1.0,
        suid_total_range=(28, 60),
        sudo_all_p=0.75,
        sudo_nopasswd_p=0.2,
        count=n - 2 * per,
    )
    df = (
        pd.concat([low, med, high], ignore_index=True)
        .sample(frac=1, random_state=seed)
        .reset_index(drop=True)
    )
    # Reindex to feature-column order, guaranteed.
    return df.reindex(columns=FEATURE_COLUMNS + ["risk_label"], fill_value=0)


def train(output_path: Path | None = None, n: int = 1500, seed: int = RNG_SEED) -> dict[str, Any]:
    """Train, evaluate, persist. Returns metadata dict."""
    settings = get_settings()
    output_path = output_path or Path(settings.model_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    df = synthesize(n=n, seed=seed)
    features = df[FEATURE_COLUMNS]
    y = df["risk_label"].astype(int)

    x_train, x_test, y_train, y_test = train_test_split(
        features, y, test_size=0.2, random_state=seed, stratify=y
    )
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=7,
        random_state=seed,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(x_train, y_train)
    y_pred = model.predict(x_test)
    accuracy = float(model.score(x_test, y_test))
    report = classification_report(
        y_test, y_pred, target_names=["LOW", "MEDIUM", "HIGH"], output_dict=True, zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred).tolist()

    trained_at = datetime.now(UTC).isoformat()
    meta = {
        "version": MODEL_VERSION,
        "trained_at": trained_at,
        "seed": seed,
        "n_samples": int(n),
        "params": {
            "n_estimators": 300,
            "max_depth": 7,
            "class_weight": "balanced",
        },
        "accuracy": accuracy,
        "classification_report": report,
        "confusion_matrix": cm,
        "feature_columns": FEATURE_COLUMNS,
    }

    # Save model + features (so infer.py can verify they match).
    payload = {"model": model, "features": FEATURE_COLUMNS, "meta": meta}
    joblib.dump(payload, output_path)

    # Compute and persist sha256 alongside. Use this value in MODEL_SHA256 env var.
    digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
    meta["sha256"] = digest

    # Rewrite with sha256 inside meta so the model knows its own identity.
    payload["meta"] = meta
    joblib.dump(payload, output_path)

    # Write a sidecar meta file for CI / release manifest.
    meta_path = output_path.with_name(output_path.stem + "_meta.json")
    meta_path.write_text(json.dumps(meta, indent=2))

    _log.info(
        "Trained v%s | accuracy=%.4f | sha256=%s | path=%s",
        MODEL_VERSION,
        accuracy,
        digest[:12],
        output_path,
    )
    print(f"\n[+] model.pkl written to {output_path}")
    print(f"[+] SHA256: {digest}")
    print(f"[+] Accuracy on held-out: {accuracy:.4f}")
    print(f"[+] meta: {meta_path}")
    print("\nAdd to .env:  MODEL_SHA256=" + digest)

    return meta


if __name__ == "__main__":
    train()
