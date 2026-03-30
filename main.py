"""
main.py — Entry Point
CipherAudit | TLS & PKI Certificate Compliance Scanner

Orchestrates all modules:
  1. Reads domain list from targets.txt or CLI argument
  2. Scans all domains concurrently using ThreadPoolExecutor
  3. Analyses each result for risk severity
  4. Persists results to SQLite
  5. Displays Rich terminal output with colour-coded table
  6. Generates PDF report

Usage:
  python main.py                        # Uses targets.txt
  python main.py --targets domains.txt  # Custom targets file
  python main.py --domains google.com hsbc.com  # Inline domains
  python main.py --no-report            # Skip PDF generation
  python main.py --threads 20           # Custom thread count (default: 20)
"""

import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich import box
from rich.text import Text

import scanner
import analyser
import database
import report as report_module

console = Console()

# Severity → Rich colour mapping
SEVERITY_COLOURS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "bold green",
    "UNKNOWN":  "dim",
}

DEFAULT_TARGETS_FILE = Path(__file__).parent / "targets.txt"
DEFAULT_THREADS = 20
LOG_FORMAT = "%(asctime)s %(levelname)-8s %(message)s"


def load_targets(targets_file: Path) -> list[str]:
    """Read domain list from a text file, skipping blank lines and comments."""
    if not targets_file.exists():
        console.print(f"[red]Error:[/red] Targets file not found: {targets_file}")
        sys.exit(1)

    domains = []
    with open(targets_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)

    if not domains:
        console.print("[red]Error:[/red] No valid domains found in targets file.")
        sys.exit(1)

    return domains


def scan_and_analyse(hostname: str) -> dict | None:
    """
    Full pipeline for a single host: scan → analyse.
    Returns analysis dict on success, or a failed-placeholder dict on error.
    """
    raw = scanner.scan_host(hostname)
    if raw is None:
        return {"hostname": hostname, "_failed": True}
    return analyser.analyse(raw)


def run_scan(domains: list[str], max_workers: int) -> list[dict]:
    """
    Scan all domains concurrently. Returns list of analysis results,
    preserving failed hosts as placeholder entries.
    """
    results = []
    total = len(domains)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning {total} domains...", total=total
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_host = {
                executor.submit(scan_and_analyse, host): host
                for host in domains
            }

            for future in as_completed(future_to_host):
                hostname = future_to_host[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as exc:
                    logging.warning("Unexpected error scanning %s: %s", hostname, exc)
                    results.append({"hostname": hostname, "_failed": True})

                progress.advance(task)

    return results


def persist_results(results: list[dict]) -> None:
    """Save all results to SQLite. Failed hosts get placeholder rows."""
    database.init_db()
    for result in results:
        if result.get("_failed"):
            database.save_failed(result["hostname"])
        else:
            database.save_result(result)


def print_summary_table(results: list[dict]) -> None:
    """Render a colour-coded summary table in the terminal using Rich."""
    # Sort by severity priority
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    sorted_results = sorted(
        results,
        key=lambda r: severity_order.get(r.get("severity", "UNKNOWN"), 4)
    )

    table = Table(
        title="CipherAudit — Scan Results",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Domain",       style="white",      min_width=28)
    table.add_column("Severity",     justify="center",   min_width=10)
    table.add_column("Days Left",    justify="right",    min_width=10)
    table.add_column("TLS",          justify="center",   min_width=9)
    table.add_column("Issuer",       min_width=20)
    table.add_column("Notes",        min_width=40)

    for r in sorted_results:
        severity = r.get("severity", "UNKNOWN")
        colour   = SEVERITY_COLOURS.get(severity, "white")
        days     = r.get("days_left")
        days_str = str(days) if days is not None else "—"

        table.add_row(
            r.get("hostname", ""),
            Text(severity, style=colour),
            days_str,
            r.get("tls_version") or "—",
            r.get("issuer") or "—",
            (r.get("notes") or "—")[:70],
        )

    console.print(table)

    # Print severity summary counts
    summary = database.get_severity_summary()
    console.print(
        f"\n  Summary — "
        f"[bold red]CRITICAL: {summary['CRITICAL']}[/bold red]  "
        f"[bold yellow]HIGH: {summary['HIGH']}[/bold yellow]  "
        f"[yellow]MEDIUM: {summary['MEDIUM']}[/yellow]  "
        f"[bold green]LOW: {summary['LOW']}[/bold green]  "
        f"[dim]UNKNOWN: {summary['UNKNOWN']}[/dim]\n"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CipherAudit — TLS & PKI Certificate Compliance Scanner"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--targets", type=Path, default=DEFAULT_TARGETS_FILE,
        help="Path to targets file (default: targets.txt)"
    )
    group.add_argument(
        "--domains", nargs="+", metavar="DOMAIN",
        help="One or more domains to scan inline"
    )
    parser.add_argument(
        "--threads", type=int, default=DEFAULT_THREADS,
        help=f"Number of concurrent scan threads (default: {DEFAULT_THREADS})"
    )
    parser.add_argument(
        "--no-report", action="store_true",
        help="Skip PDF report generation"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable debug logging"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format=LOG_FORMAT,
    )

    console.rule("[bold cyan]CipherAudit[/bold cyan]")
    console.print("[dim]TLS & PKI Certificate Compliance Scanner[/dim]\n")

    # -- Load targets -------------------------------------------------------
    if args.domains:
        domains = args.domains
    else:
        domains = load_targets(args.targets)

    console.print(f"  Loaded [bold]{len(domains)}[/bold] target domains")
    console.print(f"  Threads: [bold]{args.threads}[/bold]")
    console.print()

    # -- Scan ---------------------------------------------------------------
    results = run_scan(domains, max_workers=args.threads)

    # -- Persist ------------------------------------------------------------
    persist_results(results)

    # -- Display ------------------------------------------------------------
    print_summary_table(results)

    # -- PDF Report ---------------------------------------------------------
    if not args.no_report:
        pdf_rows = database.get_latest_scan()
        summary  = database.get_severity_summary()
        pdf_path = report_module.generate_report(pdf_rows, summary)
        console.print(f"  PDF report saved to: [bold green]{pdf_path}[/bold green]\n")
    else:
        console.print("  [dim]PDF report skipped (--no-report)[/dim]\n")

    console.rule("[dim]Done[/dim]")


if __name__ == "__main__":
    main()
