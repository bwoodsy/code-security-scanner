"""Main report generator that coordinates different report formats."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from securecode.reporters.html_reporter import HTMLReporter
from securecode.reporters.json_reporter import JSONReporter

if TYPE_CHECKING:
    from securecode.core.finding import ScanResult


class ReportGenerator:
    """Generates reports in multiple formats from scan results."""

    def __init__(self) -> None:
        """Initialize the report generator."""
        self._json_reporter = JSONReporter()
        self._html_reporter = HTMLReporter()

    def generate_json(self, result: ScanResult, output_path: Path) -> None:
        """Generate a JSON report.

        Args:
            result: Scan results to report
            output_path: Path to write the report to
        """
        self._json_reporter.generate(result, output_path)

    def generate_html(self, result: ScanResult, output_path: Path) -> None:
        """Generate an HTML report.

        Args:
            result: Scan results to report
            output_path: Path to write the report to
        """
        self._html_reporter.generate(result, output_path)

    def generate_all(
        self,
        result: ScanResult,
        output_dir: Path,
        base_name: str = "securecode-report",
    ) -> dict[str, Path]:
        """Generate reports in all supported formats.

        Args:
            result: Scan results to report
            output_dir: Directory to write reports to
            base_name: Base name for report files

        Returns:
            Dictionary mapping format names to output paths
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        paths = {}

        json_path = output_dir / f"{base_name}.json"
        self.generate_json(result, json_path)
        paths["json"] = json_path

        html_path = output_dir / f"{base_name}.html"
        self.generate_html(result, html_path)
        paths["html"] = html_path

        return paths

    def to_json_string(self, result: ScanResult) -> str:
        """Generate JSON report as a string.

        Args:
            result: Scan results to report

        Returns:
            JSON report content
        """
        return self._json_reporter.to_string(result)

    def to_html_string(self, result: ScanResult) -> str:
        """Generate HTML report as a string.

        Args:
            result: Scan results to report

        Returns:
            HTML report content
        """
        return self._html_reporter.to_string(result)
