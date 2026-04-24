"""
Priv-Eye agent CLI.

Subcommands:
- `scan`      Run recon + upload (or --dry-run to print only).
- `version`   Print agent version.
- `selftest`  Verify env vars + network reachability without sending a real scan.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .recon import collect
from .transport import AgentCredentials, TransportError, upload_scan

app = typer.Typer(
    name="priveye-agent",
    help="Priv-Eye host-posture collection agent.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )


def _render_result(result: dict) -> None:
    risk = result.get("risk", "?")
    score = result.get("score", "?")
    reasons = result.get("reasons", [])
    color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(risk, "white")
    console.print(
        Panel.fit(
            f"[bold {color}]{risk}[/] — score [bold]{score}/100[/]",
            title="Priv-Eye analysis",
            border_style=color,
        )
    )
    if reasons:
        table = Table(show_header=False, box=None, padding=(0, 1))
        for r in reasons:
            table.add_row("•", r)
        console.print(table)


@app.command()
def scan(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Collect but do not upload.")] = False,
    insecure: Annotated[bool, typer.Option("--insecure", help="Skip TLS verification (NOT for prod).")] = False,
    verbose: Annotated[bool, typer.Option("-v", "--verbose", help="Debug logs to stderr.")] = False,
    timeout: Annotated[float, typer.Option("--timeout", help="Per-probe timeout in seconds.")] = 20.0,
) -> None:
    """Collect host telemetry and send it to the Priv-Eye API."""
    _configure_logging(verbose)

    if insecure:
        console.print("[bold red]WARNING:[/] TLS verification is disabled.")

    with console.status("Collecting telemetry..."):
        result = collect(timeout_per_probe=timeout)

    payload = result.to_payload()

    if result.degraded_probes:
        console.print(
            f"[yellow]Some probes were degraded:[/] {', '.join(result.degraded_probes)}"
        )

    if dry_run:
        console.print(Panel("Dry run — payload below, not uploaded.", border_style="cyan"))
        console.print_json(json.dumps(payload))
        raise typer.Exit(0)

    try:
        creds = AgentCredentials.from_env()
    except TransportError as e:
        console.print(f"[bold red]Config error:[/] {e}")
        raise typer.Exit(2) from e

    try:
        analysis = upload_scan(payload, creds, verify_tls=not insecure)
    except TransportError as e:
        console.print(f"[bold red]Upload failed:[/] {e}")
        raise typer.Exit(1) from e

    _render_result(analysis)


@app.command()
def selftest(
    insecure: Annotated[bool, typer.Option("--insecure")] = False,
) -> None:
    """Verify env vars + reach the API's /healthz endpoint."""
    try:
        creds = AgentCredentials.from_env()
    except TransportError as e:
        console.print(f"[bold red]Config error:[/] {e}")
        raise typer.Exit(2) from e

    try:
        resp = httpx.get(f"{creds.api_base}/healthz", timeout=10.0, verify=not insecure)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        console.print(f"[bold red]Cannot reach API:[/] {e}")
        raise typer.Exit(1) from e

    console.print(f"[green]OK[/] — {creds.api_base} responded {resp.status_code}")


@app.command()
def version() -> None:
    """Print agent version."""
    console.print(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
