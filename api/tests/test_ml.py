"""ML pipeline tests — pure unit tests, no DB or HTTP needed."""

from __future__ import annotations

import pytest

from priveye_api.ml.features import FEATURE_COLUMNS, build_feature_vector
from priveye_api.ml.infer import ModelNotLoadedError, predict


def test_feature_vector_length() -> None:
    fv = build_feature_vector(
        kernel_version="5.15.0-generic",
        suid_binaries=["pkexec", "sudo"],
        sudo_privileges="(ALL : ALL) ALL",
        euid=1000,
    )
    assert len(fv.values) == len(FEATURE_COLUMNS)


def test_hvt_detection() -> None:
    fv = build_feature_vector(
        kernel_version="5.15.0",
        suid_binaries=["pkexec", "sudo"],
        sudo_privileges="",
        euid=1000,
    )
    assert fv.humanized["suid_pkexec"] == 1.0
    assert fv.humanized["suid_sudo"] == 1.0
    assert fv.humanized["suid_su"] == 0.0


def test_nopasswd_detection() -> None:
    fv = build_feature_vector(
        kernel_version="5.15.0",
        suid_binaries=[],
        sudo_privileges="(ALL) NOPASSWD: ALL",
        euid=0,
    )
    assert fv.humanized["sudo_has_nopasswd"] == 1.0
    assert fv.humanized["euid_is_root"] == 1.0


def test_kernel_parse() -> None:
    fv = build_feature_vector(
        kernel_version="6.1.38-ubuntu",
        suid_binaries=[],
        sudo_privileges="",
        euid=1000,
    )
    assert fv.humanized["kernel_major"] == 6.0
    assert fv.humanized["kernel_minor"] == 1.0
    assert fv.humanized["kernel_flavor_ubuntu"] == 1.0


def test_predict_valid_output() -> None:
    try:
        result = predict(
            {
                "kernel_version": "5.15.0-generic",
                "suid_binaries": ["pkexec"],
                "sudo_privileges": "(ALL) NOPASSWD: ALL",
                "euid": 0,
            }
        )
        assert result["risk"] in ("LOW", "MEDIUM", "HIGH")
        assert 0 <= result["score"] <= 100
        assert abs(sum(result["probabilities"].values()) - 1.0) < 0.01
    except ModelNotLoadedError:
        pytest.skip("model.pkl not present — run train step first")


def test_clean_host_not_high_risk() -> None:
    try:
        result = predict(
            {
                "kernel_version": "6.5.0-rhel",
                "suid_binaries": [],
                "sudo_privileges": "",
                "euid": 1000,
            }
        )
        assert result["risk"] != "HIGH"
    except ModelNotLoadedError:
        pytest.skip("model.pkl not present")
