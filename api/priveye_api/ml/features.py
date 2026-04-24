"""
Feature engineering — ported from v1's `ml_pipeline.py`.

Only change vs v1: stricter bounds on inputs (already done via Pydantic upstream,
reinforced here with defensive clamping) and explicit feature ordering so
inference matches training exactly.

Control refs:
- ASVS V5.1.4 / NIST SI-10 — bounds check before model input
- OWASP ML05 — constrain feature vector
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Authoritative column order. MUST match training script. Changing this is a
# model-breaking change — bump MODEL_VERSION in infer.py.
FEATURE_COLUMNS: list[str] = [
    "kernel_major",
    "kernel_minor",
    "kernel_patch",
    "suid_pkexec",
    "suid_su",
    "suid_sudo",
    "suid_mount",
    "suid_passwd",
    "suid_chsh",
    "suid_total_count",
    "sudo_has_all",
    "sudo_has_nopasswd",
    "euid_is_root",
    # kernel_flavor one-hots, expanded in training
    "kernel_flavor_standard",
    "kernel_flavor_ubuntu",
    "kernel_flavor_debian",
    "kernel_flavor_rhel",
    "kernel_flavor_kali-amd64",
    "kernel_flavor_unknown",
]

HVT_BASENAMES = ("pkexec", "su", "sudo", "mount", "passwd", "chsh")
KNOWN_FLAVORS = ("standard", "ubuntu", "debian", "rhel", "kali-amd64")

_KERNEL_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,4})(.*)$")


@dataclass(frozen=True)
class FeatureVector:
    values: list[float]  # aligned with FEATURE_COLUMNS
    humanized: dict[str, float]  # same data, name-keyed, for the API response


def _parse_kernel(kernel_str: str) -> tuple[int, int, int, str]:
    m = _KERNEL_RE.match(kernel_str.strip())
    if not m:
        return 0, 0, 0, "unknown"
    major, minor, patch, tail = m.groups()
    flavor = "standard"
    tail = tail.lower().strip("-+_")
    for f in KNOWN_FLAVORS:
        if f in tail:
            flavor = f
            break
    return int(major), int(minor), int(patch), flavor


def _encode_suids(suid_list: list[str]) -> dict[str, int]:
    basenames = [p.rsplit("/", 1)[-1] for p in suid_list]
    out = {f"suid_{t}": int(t in basenames) for t in HVT_BASENAMES}
    out["suid_total_count"] = min(len(suid_list), 2000)  # clamp consistent with schema
    return out


def _parse_sudo(sudo_str: str, euid: int) -> dict[str, int]:
    s = sudo_str or ""
    return {
        "sudo_has_all": int("(ALL : ALL) ALL" in s or "(ALL) ALL" in s),
        "sudo_has_nopasswd": int("NOPASSWD" in s),
        "euid_is_root": int(euid == 0),
    }


def build_feature_vector(
    *,
    kernel_version: str,
    suid_binaries: list[str],
    sudo_privileges: str,
    euid: int,
) -> FeatureVector:
    """Turn validated telemetry into a model-ready feature vector."""
    k_maj, k_min, k_pat, k_flav = _parse_kernel(kernel_version)
    features: dict[str, float] = {
        "kernel_major": k_maj,
        "kernel_minor": k_min,
        "kernel_patch": k_pat,
        **{f"kernel_flavor_{f}": int(k_flav == f) for f in KNOWN_FLAVORS},
        "kernel_flavor_unknown": int(k_flav == "unknown"),
        **{k: float(v) for k, v in _encode_suids(suid_binaries).items()},
        **{k: float(v) for k, v in _parse_sudo(sudo_privileges, euid).items()},
    }

    # Reindex to the authoritative order. Missing columns default to 0.
    values = [float(features.get(col, 0.0)) for col in FEATURE_COLUMNS]
    humanized = dict(zip(FEATURE_COLUMNS, values))
    return FeatureVector(values=values, humanized=humanized)
