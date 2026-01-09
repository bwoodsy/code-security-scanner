"""Command-line interface for SecureCode-AI."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

# Windows-safe spinner
SPINNER = "dots" if sys.platform != "win32" else "line"

from securecode import __version__
from securecode.config import AppSettings, ScanConfig, load_config_file, setup_logging
from securecode.core.finding import Severity
from securecode.orchestrator import ScanOrchestrator
from securecode.reporters import ReportGenerator

# Initialize Typer app
app = typer.Typer(
    name="securecode",
    help="Static code security scanner for TypeScript and C# codebases.",
    add_completion=False,
    no_args_is_help=True,
)

# Force UTF-8 on Windows to avoid encoding issues
if sys.platform == "win32":
    import os
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    # Enable VT100 escape sequences on Windows 10+
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# Use ASCII-safe output on Windows
console = Console(force_terminal=True, legacy_windows=True if sys.platform == "win32" else False)

# ASCII-safe divider character
DIVIDER = "-" if sys.platform == "win32" else "━"


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"[bold blue]SecureCode-AI[/bold blue] version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """SecureCode-AI: Static code security scanner."""
    pass


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Argument(
            help="Directory or file to scan (defaults to current directory)",
            exists=True,
            resolve_path=True,
        ),
    ] = Path("."),
    output: Annotated[
        str,
        typer.Option(
            "--output",
            "-o",
            help="Output format: json, html, or both",
        ),
    ] = "both",
    severity: Annotated[
        str,
        typer.Option(
            "--severity",
            "-s",
            help="Minimum severity: critical, high, medium, low, info",
        ),
    ] = "low",
    languages: Annotated[
        Optional[str],
        typer.Option(
            "--languages",
            "-l",
            help="Languages to scan (comma-separated): ts, cs",
        ),
    ] = None,
    exclude: Annotated[
        Optional[str],
        typer.Option(
            "--exclude",
            "-e",
            help="Directories to exclude (comma-separated)",
        ),
    ] = None,
    output_dir: Annotated[
        Optional[Path],
        typer.Option(
            "--output-dir",
            "-d",
            help="Directory for report output",
        ),
    ] = None,
    config: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-c",
            help="Path to configuration file",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            help="Enable verbose output",
        ),
    ] = False,
    no_fail: Annotated[
        bool,
        typer.Option(
            "--no-fail",
            help="Don't exit with code 1 when vulnerabilities are found",
        ),
    ] = False,
) -> None:
    """Scan a directory or file for security vulnerabilities."""
    # Setup logging
    settings = AppSettings()
    if verbose:
        settings.log_level = "DEBUG"
    setup_logging(settings)

    # Print header
    console.print()
    console.print(
        Panel.fit(
            f"[bold blue]SecureCode-AI[/bold blue] v{__version__}",
            border_style="blue",
        )
    )
    console.print()

    # Load configuration
    scan_config = load_config_file(config)

    # Apply CLI overrides
    if output_dir:
        scan_config.output_dir = output_dir
    if exclude:
        scan_config.exclude_dirs.extend(exclude.split(","))
    if languages:
        scan_config.languages = [lang.strip() for lang in languages.split(",")]

    # Parse severity
    try:
        scan_config.severity_threshold = Severity(severity.upper())
    except ValueError:
        console.print(f"[red]Invalid severity level: {severity}[/red]")
        raise typer.Exit(2)

    # Parse output formats
    output_formats = []
    if output.lower() in ("json", "both"):
        output_formats.append("json")
    if output.lower() in ("html", "both"):
        output_formats.append("html")
    scan_config.output_formats = output_formats

    scan_config.fail_on_findings = not no_fail
    scan_config.verbose = verbose

    # Create output directory
    scan_config.output_dir.mkdir(parents=True, exist_ok=True)

    # Run scan
    console.print(f"[bold]Scanning:[/bold] {path}")

    orchestrator = ScanOrchestrator(scan_config)

    with Progress(
        SpinnerColumn(spinner_name=SPINNER),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Discovering files...", total=None)

        result = orchestrator.scan(path, progress_callback=lambda msg: progress.update(task, description=msg))

    # Print summary
    console.print()
    _print_summary(result.summary, result.metadata)

    # Generate reports
    if result.vulnerabilities:
        timestamp = datetime.now().strftime("%Y-%m-%dT%H%M%S")
        report_gen = ReportGenerator()

        for fmt in scan_config.output_formats:
            report_path = scan_config.output_dir / f"securecode-report-{timestamp}.{fmt}"
            if fmt == "json":
                report_gen.generate_json(result, report_path)
            elif fmt == "html":
                report_gen.generate_html(result, report_path)
            console.print(f"[green]->[/green] {report_path}")

    console.print()

    # Exit with appropriate code
    if result.vulnerabilities and scan_config.fail_on_findings:
        raise typer.Exit(1)
    raise typer.Exit(0)


@app.command()
def check(
    file: Annotated[
        Path,
        typer.Argument(
            help="File to check",
            exists=True,
            resolve_path=True,
        ),
    ],
) -> None:
    """Quick check a single file for vulnerabilities."""
    settings = AppSettings()
    setup_logging(settings)

    console.print(f"[bold]Checking:[/bold] {file}")

    config = ScanConfig(output_formats=[])
    orchestrator = ScanOrchestrator(config)

    result = orchestrator.scan_single_file(file)

    if not result:
        console.print("[green]No vulnerabilities found.[/green]")
        raise typer.Exit(0)

    console.print(f"\n[bold red]Found {len(result)} vulnerability(ies):[/bold red]\n")

    for vuln in result:
        severity_color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange1",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }.get(vuln.severity, "white")

        console.print(f"[{severity_color}][{vuln.severity.value}][/{severity_color}] {vuln.title}")
        console.print(f"  Line {vuln.line}: {vuln.matched_code[:80]}")
        console.print(f"  [dim]{vuln.description[:100]}...[/dim]")
        console.print()

    raise typer.Exit(1)


def _print_summary(summary: "ScanSummary", metadata: "ScanMetadata") -> None:
    """Print scan summary to console."""
    from securecode.core.finding import ScanMetadata, ScanSummary

    console.print("[bold]SCAN COMPLETE[/bold]")
    console.print(DIVIDER * 50)
    console.print()

    # Summary table
    table = Table(show_header=False, box=None)
    table.add_column("Label", style="bold")
    table.add_column("Value")

    table.add_row("Files scanned", str(metadata.files_scanned))
    table.add_row("Scan duration", f"{metadata.scan_duration_seconds:.2f}s")
    table.add_row("Languages", ", ".join(metadata.languages_scanned) or "N/A")

    console.print(table)
    console.print()

    # Severity breakdown
    if summary.total_vulnerabilities > 0:
        console.print("[bold]Vulnerabilities by Severity:[/bold]")

        severity_table = Table(show_header=False, box=None)
        severity_table.add_column("Severity", width=12)
        severity_table.add_column("Count", justify="right")

        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = summary.by_severity.get(sev, 0)
            if count > 0:
                color = severity_colors.get(sev, "white")
                severity_table.add_row(f"[{color}]{sev}[/{color}]", str(count))

        severity_table.add_row(DIVIDER * 10, DIVIDER * 5)
        severity_table.add_row("[bold]TOTAL[/bold]", f"[bold]{summary.total_vulnerabilities}[/bold]")

        console.print(severity_table)
        console.print()

        # Top vulnerable files
        if summary.top_vulnerable_files:
            console.print("[bold]Top Vulnerable Files:[/bold]")
            for i, file_info in enumerate(summary.top_vulnerable_files[:5], 1):
                console.print(f"  {i}. {file_info['file']} ({file_info['count']} issues)")
            console.print()
    else:
        console.print("[green]No vulnerabilities found![/green]")
        console.print()


if __name__ == "__main__":
    app()
