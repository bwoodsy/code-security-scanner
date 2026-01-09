"""HTML report generator."""

from __future__ import annotations

import html
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, PackageLoader, select_autoescape

from securecode.core.finding import Severity
from securecode.core.statistics import calculate_statistics, estimate_finding_fp_probability
from securecode.reporters.base import BaseReporter

if TYPE_CHECKING:
    from securecode.core.finding import ScanResult


class HTMLReporter(BaseReporter):
    """Generates HTML reports from scan results."""

    def __init__(self) -> None:
        """Initialize the HTML reporter."""
        self._env = Environment(
            loader=PackageLoader("securecode", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self._env.filters["severity_color"] = self._severity_color
        self._env.filters["severity_bg"] = self._severity_bg

    @property
    def format_name(self) -> str:
        """Name of the output format."""
        return "html"

    @property
    def file_extension(self) -> str:
        """File extension for output files."""
        return ".html"

    def generate(self, result: ScanResult, output_path: Path) -> None:
        """Generate an HTML report file.

        Args:
            result: The scan results to report
            output_path: Path to write the report to
        """
        content = self.to_string(result)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

    def to_string(self, result: ScanResult) -> str:
        """Generate report as an HTML string.

        Args:
            result: The scan results to report

        Returns:
            HTML report content
        """
        template = self._env.get_template("report.html.j2")

        # Group vulnerabilities by file
        vulns_by_file: dict[str, list] = {}
        for vuln in result.vulnerabilities:
            file_key = str(vuln.relative_path)
            if file_key not in vulns_by_file:
                vulns_by_file[file_key] = []
            vulns_by_file[file_key].append(vuln)

        # Sort by severity within each file
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        for file_vulns in vulns_by_file.values():
            file_vulns.sort(key=lambda v: severity_order.get(v.severity, 5))

        # Get critical vulnerabilities for highlight section
        critical_vulns = [
            v for v in result.vulnerabilities
            if v.severity in [Severity.CRITICAL, Severity.HIGH]
        ]

        # Calculate statistics
        stats = calculate_statistics(result.vulnerabilities)
        stats.total_files = result.metadata.files_scanned

        # Add FP probability to each vulnerability for display
        vuln_fp_probs = {
            v.id: round(estimate_finding_fp_probability(v) * 100, 1)
            for v in result.vulnerabilities
        }

        return template.render(
            result=result,
            metadata=result.metadata,
            summary=result.summary,
            vulnerabilities=result.vulnerabilities,
            vulns_by_file=vulns_by_file,
            critical_vulns=critical_vulns[:10],  # Limit to top 10
            severity_order=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            statistics=stats,
            vuln_fp_probs=vuln_fp_probs,
        )

    @staticmethod
    def _severity_color(severity: str) -> str:
        """Get the text color for a severity level."""
        colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
            "INFO": "#6b7280",
        }
        return colors.get(severity, "#6b7280")

    @staticmethod
    def _severity_bg(severity: str) -> str:
        """Get the background color for a severity level."""
        colors = {
            "CRITICAL": "#fef2f2",
            "HIGH": "#fff7ed",
            "MEDIUM": "#fefce8",
            "LOW": "#eff6ff",
            "INFO": "#f9fafb",
        }
        return colors.get(severity, "#f9fafb")
