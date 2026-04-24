# priveye-agent

Linux host-posture collection agent for Priv-Eye. Runs a fixed set of read-only reconnaissance probes, packages the result as a signed JSON payload, and POSTs it to the API.

## Security properties

- **No `shell=True`.** All subprocess calls use argv lists; untrusted output is never re-evaluated.
- **Per-call timeouts.** `find`, `sudo -l`, etc. have hard timeouts so a runaway probe cannot hang the agent indefinitely.
- **Least-privilege by default.** Runs as the invoking user; SUID discovery is best-effort when not root. The API does not require root-level telemetry.
- **HMAC-signed requests.** Canonical form `timestamp + "\n" + nonce + "\n" + body`, HMAC-SHA256, constant-time compared server-side.
- **No credentials in argv.** HMAC key is read from the environment (`PRIVEYE_HMAC_KEY`) or a mode-600 credentials file. Never passed on the command line.
- **Certificate validation.** TLS verification is on by default; disabling it requires an explicit `--insecure` flag and prints a red warning.

## Install

```bash
pip install -e .
# or from release wheel
pip install priveye-agent
```

## Configure

```bash
export PRIVEYE_API="https://priveye.example.com"
export PRIVEYE_HOST_ID="<id from /api/v1/hosts response>"
export PRIVEYE_HMAC_KEY="<one-time key shown at host creation>"
```

## Run a scan

```bash
priveye-agent scan
```

Dry-run (recon only, no upload):

```bash
priveye-agent scan --dry-run
```

## What it collects

| Field              | Source                      | Purpose                              |
| ------------------ | --------------------------- | ------------------------------------ |
| `kernel_version`   | `uname -r`                  | CVE lookup, kernel age heuristic     |
| `euid`             | `os.geteuid()`              | Privilege context of the scan        |
| `suid_binaries`    | `find / -perm -4000 ...`    | HVT (high-value-target) detection    |
| `sudo_privileges`  | `sudo -l -n`                | NOPASSWD / ALL abuse detection       |

That's it. No process lists, no file contents, no network introspection, no user data.
