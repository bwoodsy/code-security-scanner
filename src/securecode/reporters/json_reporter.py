"""JSON report generator."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from securecode.core.finding import ScanResult
from securecode.core.statistics import calculate_statistics, estimate_finding_fp_probability
from securecode.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    """Generates JSON reports from scan results."""

    @property
    def format_name(self) -> str:
        """Name of the output format."""
        return "json"

    @property
    def file_extension(self) -> str:
        """File extension for output files."""
        return ".json"

    def generate(self, result: ScanResult, output_path: Path) -> None:
        """Generate a JSON report file.

        Args:
            result: The scan results to report
            output_path: Path to write the report to
        """
        content = self.to_string(result)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

    def to_string(self, result: ScanResult) -> str:
        """Generate report as a JSON string.

        Args:
            result: The scan results to report

        Returns:
            JSON report content
        """
        data = self._serialize_result(result)
        return json.dumps(data, indent=2, default=self._json_serializer)

    def _serialize_result(self, result: ScanResult) -> dict[str, Any]:
        """Serialize ScanResult to a dictionary."""
        # Calculate statistics
        stats = calculate_statistics(result.vulnerabilities)
        stats.total_files = result.metadata.files_scanned

        return {
            "schema_version": result.schema_version,
            "scan_metadata": {
                "scan_id": result.metadata.scan_id,
                "timestamp": result.metadata.timestamp.isoformat(),
                "scanner_version": result.metadata.scanner_version,
                "target_directory": str(result.metadata.target_directory),
                "files_scanned": result.metadata.files_scanned,
                "files_with_errors": result.metadata.files_with_errors,
                "scan_duration_seconds": result.metadata.scan_duration_seconds,
                "languages_scanned": result.metadata.languages_scanned,
                "excluded_directories": result.metadata.excluded_directories,
            },
            "summary": {
                "total_vulnerabilities": result.summary.total_vulnerabilities,
                "by_severity": result.summary.by_severity,
                "by_type": result.summary.by_type,
                "by_language": result.summary.by_language,
                "top_vulnerable_files": result.summary.top_vulnerable_files,
            },
            "statistics": stats.to_dict(),
            "vulnerabilities": [
                {
                    "id": v.id,
                    "rule_id": v.rule_id,
                    "file_path": str(v.file_path),
                    "relative_path": str(v.relative_path),
                    "line": v.line,
                    "column": v.column,
                    "end_line": v.end_line,
                    "end_column": v.end_column,
                    "code_snippet": v.code_snippet,
                    "matched_code": v.matched_code,
                    "vulnerability_type": v.vulnerability_type.value,
                    "severity": v.severity.value,
                    "confidence": v.confidence.value,
                    "title": v.title,
                    "description": v.description,
                    "remediation": v.remediation,
                    "cwe_id": v.cwe_id,
                    "owasp_category": v.owasp_category,
                    "language": v.language,
                    "metadata": {k: v for k, v in v.metadata.items() if k != "deep_analysis"} if v.metadata else {},
                    "deep_analysis": v.metadata.get("deep_analysis") if v.metadata else None,
                    "fp_probability": round(estimate_finding_fp_probability(v) * 100, 1),
                }
                for v in result.vulnerabilities
            ],
        }

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for non-standard types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
