"""
Read-only host reconnaissance.

Hardening:
- NEVER uses shell=True. All probes are argv lists.
- Per-probe hard timeout (default 20s each).
- Broad exceptions are caught and converted to degraded fields — the agent
  should always produce *something* to send, even from a locked-down box,
  rather than crashing.
- No file contents are read. Only shape/metadata.

Ported from Priv-Eye v1's LinuxReconEngine, but stripped of shell invocation
and with stricter output shaping (the v1 version leaked raw command output
into the payload; here we parse and keep only what the ML model needs).
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess  # noqa: S404 — subprocess is the whole point; we use it safely
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger("priveye.agent.recon")

# These are the binaries whose SUID status meaningfully moves the ML score
# in our v1 training data. Keeping the list explicit caps payload size.
_HVT_BASENAMES = {
    "pkexec",  # CVE-2021-4034 (PwnKit)
    "sudo",
    "su",
    "nmap",
    "find",
    "vim",
    "bash",
    "cp",
    "mv",
    "dd",
}

_SEARCH_ROOTS = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]


@dataclass(frozen=True)
class ReconResult:
    """Structured, API-shaped recon output."""

    kernel_version: str
    euid: int
    suid_binaries: list[str] = field(default_factory=list)
    sudo_privileges: str = ""
    degraded_probes: list[str] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        """Serialize in the exact shape the API's TelemetryPayload expects."""
        return {
            "kernel_version": self.kernel_version,
            "euid": self.euid,
            "suid_binaries": self.suid_binaries,
            "sudo_privileges": self.sudo_privileges,
        }


def _run(argv: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """Safe subprocess wrapper — no shell, explicit argv, hard timeout."""
    return subprocess.run(  # noqa: S603 — argv is a literal list, no shell
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def probe_kernel() -> str:
    """Return `uname -r` output. Falls back to platform.release()."""
    try:
        out = _run(["uname", "-r"], timeout=2.0)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()[:64]
    except (OSError, subprocess.TimeoutExpired) as e:
        _log.warning("uname probe failed: %s", e)
    # platform.release() reads /proc/sys/kernel/osrelease on Linux.
    return platform.release()[:64] or "unknown"


def probe_euid() -> int:
    """Effective UID of the agent process. 0 == root."""
    try:
        return int(os.geteuid())
    except AttributeError:
        # Non-POSIX. Shouldn't happen on the supported platforms.
        return -1


def probe_suid(timeout: float = 20.0) -> tuple[list[str], bool]:
    """
    Discover SUID HVT binaries.

    Returns (list_of_basenames_found, degraded_flag).

    Strategy: walk a small set of canonical bin dirs with `find ... -perm -4000`.
    We do NOT walk `/` — v1 did that, and it both took minutes and triggered
    Linux audit noise. For our ML features we only care about the HVT set.
    """
    if not shutil.which("find"):
        return [], True

    existing_roots = [r for r in _SEARCH_ROOTS if os.path.isdir(r)]
    if not existing_roots:
        return [], True

    argv = ["find", *existing_roots, "-xdev", "-type", "f", "-perm", "-4000"]
    try:
        out = _run(argv, timeout=timeout)
    except subprocess.TimeoutExpired:
        _log.warning("find timed out after %ss", timeout)
        return [], True
    except OSError as e:
        _log.warning("find failed: %s", e)
        return [], True

    found: set[str] = set()
    for line in out.stdout.splitlines():
        basename = os.path.basename(line.strip())
        if basename in _HVT_BASENAMES:
            found.add(basename)

    # Always return stable ordering so the ML feature vector is deterministic.
    return sorted(found), False


def probe_sudo(timeout: float = 10.0) -> tuple[str, bool]:
    """
    Run `sudo -l -n`. Non-interactive (-n) so we never prompt.

    Returns (stdout_str_capped, degraded_flag). If sudo isn't installed or
    asks for a password, we return "" and degraded=True.
    """
    if not shutil.which("sudo"):
        return "", True

    try:
        out = _run(["sudo", "-l", "-n"], timeout=timeout)
    except subprocess.TimeoutExpired:
        return "", True
    except OSError:
        return "", True

    # sudo returns non-zero when a password would be required. That's fine —
    # we just can't enumerate, so treat it as degraded rather than failure.
    if out.returncode != 0:
        return "", True

    # Cap to a sensible length. The API schema also caps.
    return out.stdout[:4096], False


def collect(timeout_per_probe: float = 20.0) -> ReconResult:
    """
    Run all probes in parallel and assemble a ReconResult.

    Failures are soft — a degraded probe records its name in
    `degraded_probes` rather than raising.
    """
    degraded: list[str] = []

    # Kernel + euid are cheap and sync.
    kernel = probe_kernel()
    euid = probe_euid()

    # suid + sudo can parallelize.
    suid_binaries: list[str] = []
    sudo_output = ""
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures: dict[Future[tuple[list[str] | str, bool]], str] = {
            pool.submit(probe_suid, timeout_per_probe): "suid",
            pool.submit(probe_sudo, min(timeout_per_probe, 10.0)): "sudo",
        }
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                result, was_degraded = fut.result()
            except Exception as e:  # pragma: no cover — defensive
                _log.warning("%s probe crashed: %s", name, e)
                degraded.append(name)
                continue
            if was_degraded:
                degraded.append(name)
            if name == "suid":
                suid_binaries = result  # type: ignore[assignment]
            elif name == "sudo":
                sudo_output = result  # type: ignore[assignment]

    return ReconResult(
        kernel_version=kernel,
        euid=euid,
        suid_binaries=suid_binaries,
        sudo_privileges=sudo_output,
        degraded_probes=degraded,
    )
