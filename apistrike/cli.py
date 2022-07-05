import argparse
import sys
import json
from rich.console import Console
from rich.table   import Table
from rich.panel   import Panel
from rich         import box

from .core.scanner    import Scanner, ScanConfig
from .reporting.reporter import Reporter

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "blue",
}

BANNER = r"""
[bold cyan]
   ___    ____  ____   ____  __            _  __
  / _ |  / __ \/  _/  / __/ / /____  ____ (_)/ /_____ 
 / __ | / /_/ // /   _\ \  / __/ __\/ __// // //_/ _ \\
/_/ |_|/ .___/___/  /___/  \__/_/ /_/\__/_//_/ /_/\___/
       /_/
[/bold cyan]
[dim]Automated API Security Verification Scanner v1.0.0[/dim]
[dim]For authorized security research use only.[/dim]
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apistrike",
        description="APIStrike — automated REST API security scanner",
    )

    p.add_argument("base_url", help="Target API base URL (e.g. http://localhost:5000)")
    p.add_argument(
        "--endpoints", "-e",
        nargs="+",
        metavar="URL",
        help="Explicit endpoint URLs to probe for CORS/headers. "
             "If omitted, common paths are auto-generated from base_url.",
    )
    p.add_argument(
        "--bola-templates", "-b",
        nargs="+",
        metavar="TEMPLATE",
        help="URL templates with {id} placeholder for BOLA enumeration.",
    )
    p.add_argument(
        "--engines",
        nargs="+",
        choices=["cors", "headers", "bola"],
        default=["cors", "headers", "bola"],
        help="Engines to run (default: all).",
    )
    p.add_argument("--id-start",   type=int,   default=1,    help="BOLA: start ID (default 1).")
    p.add_argument("--id-end",     type=int,   default=10,   help="BOLA: end ID (default 10).")
    p.add_argument("--delay-ms",   type=float, default=50.0, help="BOLA: ms between requests (default 50).")
    p.add_argument("--timeout",    type=int,   default=10,   help="HTTP read timeout seconds (default 10).")
    p.add_argument("--no-verify",  action="store_true",      help="Disable TLS certificate verification.")
    p.add_argument("--json-out",   metavar="FILE",           help="Save JSON report to file.")
    p.add_argument("--html-out",   metavar="FILE",           help="Save HTML report to file.")
    p.add_argument("--quiet", "-q", action="store_true",     help="Suppress progress messages.")

    return p


def default_endpoints(base_url: str):
    base = base_url.rstrip("/")
    return [
        f"{base}/api/health",
        f"{base}/api/users",
        f"{base}/api/users/1",
        f"{base}/api/products/1",
        f"{base}/api/admin/users",
    ]


def default_bola_templates(base_url: str):
    base = base_url.rstrip("/")
    return [
        f"{base}/api/users/{{id}}",
        f"{base}/api/products/{{id}}",
    ]


def print_results(result, quiet: bool):
    meta     = result.metadata
    findings = result.findings

    console.print(f"\n[bold]Scan complete[/bold] — {meta['duration_seconds']}s | "
                  f"{meta['total_findings']} finding(s) across "
                  f"{meta['endpoints_probed']} probe(s)\n")

    if not findings:
        console.print("[green]No findings detected.[/green]")
        return

    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold dim",
        border_style="dim",
    )
    table.add_column("#",          style="dim", width=4)
    table.add_column("Severity",   width=10)
    table.add_column("Engine",     width=24)
    table.add_column("Endpoint",   width=40, overflow="fold")
    table.add_column("Title",      width=45, overflow="fold")
    table.add_column("Latency ms", width=11, justify="right")

    for i, f in enumerate(findings, 1):
        style   = SEVERITY_STYLES.get(f.severity.value, "")
        latency = f.evidence.get("latency_ms", "—")
        table.add_row(
            str(i),
            f"[{style}]{f.severity.value}[/{style}]",
            f.engine,
            f.endpoint,
            f.title,
            str(latency) if latency is not None else "—",
        )

    console.print(table)

    # Summary bar
    by_sev = meta.get("findings_by_severity", {})
    parts  = []
    for sev, style in SEVERITY_STYLES.items():
        count = by_sev.get(sev, 0)
        if count:
            parts.append(f"[{style}]{sev}: {count}[/{style}]")
    console.print("  " + "  |  ".join(parts) + "\n")


def main():
    parser = build_parser()
    args   = parser.parse_args()

    console.print(BANNER)

    endpoints      = args.endpoints      or default_endpoints(args.base_url)
    bola_templates = args.bola_templates or default_bola_templates(args.base_url)

    config = ScanConfig(
        base_url       = args.base_url,
        endpoints      = endpoints,
        bola_templates = bola_templates,
        engines        = args.engines,
        bola_id_start  = args.id_start,
        bola_id_end    = args.id_end,
        bola_delay_ms  = args.delay_ms,
        timeout        = (5, args.timeout),
        verify_ssl     = not args.no_verify,
    )

    def log(msg):
        if not args.quiet:
            console.print(f"[dim]{msg}[/dim]")

    scanner = Scanner(config, progress_callback=log)

    console.print(f"[bold]Target:[/bold] {args.base_url}")
    console.print(f"[bold]Engines:[/bold] {', '.join(args.engines)}")
    console.print(f"[bold]Endpoints:[/bold] {len(endpoints)} | "
                  f"[bold]BOLA templates:[/bold] {len(bola_templates)}\n")

    result   = scanner.run()
    reporter = Reporter(result)

    print_results(result, args.quiet)

    if args.json_out:
        path = reporter.save_json(args.json_out)
        console.print(f"[green]JSON report saved:[/green] {path}")

    if args.html_out:
        path = reporter.save_html(args.html_out)
        console.print(f"[green]HTML report saved:[/green] {path}")

    # Exit with non-zero if HIGH or CRITICAL findings exist
    has_high = any(
        f.severity.value in ("HIGH", "CRITICAL")
        for f in result.findings
    )
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()
