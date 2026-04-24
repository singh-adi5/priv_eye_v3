"""Recon probe tests — focus on *safety* properties, not output correctness."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from priveye_agent import recon


def test_probe_kernel_never_empty() -> None:
    """Even when uname fails we must return *something* parseable."""
    with patch.object(recon, "_run", side_effect=OSError("boom")):
        with patch("platform.release", return_value=""):
            out = recon.probe_kernel()
    assert out == "unknown"


def test_probe_kernel_caps_length() -> None:
    """Oversized uname output must be truncated — prevents payload bloat."""
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="A" * 500, stderr="")
    with patch.object(recon, "_run", return_value=fake):
        out = recon.probe_kernel()
    assert len(out) <= 64


def test_probe_suid_timeout_returns_degraded() -> None:
    """A find timeout must degrade gracefully, not crash."""
    with patch("shutil.which", return_value="/usr/bin/find"):
        with patch("os.path.isdir", return_value=True):
            with patch.object(
                recon,
                "_run",
                side_effect=subprocess.TimeoutExpired(cmd="find", timeout=1.0),
            ):
                found, degraded = recon.probe_suid(timeout=1.0)
    assert found == []
    assert degraded is True


def test_probe_suid_filters_to_hvt_only() -> None:
    """find output with non-HVT binaries must be filtered out."""
    fake_stdout = "\n".join(
        [
            "/usr/bin/pkexec",
            "/usr/bin/ls",  # not HVT — must be dropped
            "/usr/bin/sudo",
            "/some/random/binary",
        ]
    )
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout=fake_stdout, stderr="")
    with patch("shutil.which", return_value="/usr/bin/find"):
        with patch("os.path.isdir", return_value=True):
            with patch.object(recon, "_run", return_value=fake):
                found, degraded = recon.probe_suid()
    assert set(found) == {"pkexec", "sudo"}
    assert degraded is False


def test_probe_sudo_nonzero_returns_degraded() -> None:
    """If sudo -l -n returns nonzero (pw needed), we must degrade, not raise."""
    fake = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="password required")
    with patch("shutil.which", return_value="/usr/bin/sudo"):
        with patch.object(recon, "_run", return_value=fake):
            out, degraded = recon.probe_sudo()
    assert out == ""
    assert degraded is True


def test_probe_sudo_not_installed() -> None:
    with patch("shutil.which", return_value=None):
        out, degraded = recon.probe_sudo()
    assert out == ""
    assert degraded is True


def test_collect_produces_api_shaped_payload() -> None:
    """to_payload() must exactly match the API's TelemetryPayload field set."""
    result = recon.ReconResult(
        kernel_version="6.1.0-test",
        euid=1000,
        suid_binaries=["pkexec"],
        sudo_privileges="",
    )
    payload = result.to_payload()
    assert set(payload.keys()) == {"kernel_version", "euid", "suid_binaries", "sudo_privileges"}


def test_recon_never_uses_shell_true() -> None:
    """
    Safety invariant: no code path in recon.py may invoke subprocess with
    shell=True. Parses the AST (not raw text) so docstring mentions are OK
    but actual calls are not.
    """
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path(recon.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    raise AssertionError(f"shell=True at line {node.lineno}")


@pytest.mark.parametrize(
    "argv_input",
    [
        ["uname", "-r"],
        ["find", "/usr/bin", "-perm", "-4000"],
        ["sudo", "-l", "-n"],
    ],
)
def test_run_is_argv_only(argv_input: list[str]) -> None:
    """_run must never mutate argv into a shell string."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=argv_input, returncode=0, stdout="", stderr=""
        )
        recon._run(argv_input, timeout=1.0)
        _, kwargs = mock_run.call_args
        # The argv must be passed as a list; shell must not be set True.
        assert mock_run.call_args.args[0] == argv_input
        assert kwargs.get("shell", False) is False
