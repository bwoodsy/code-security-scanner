"""Scan orchestrator for coordinating multi-language security scans."""

from __future__ import annotations

import logging
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from securecode import __version__
from securecode.analysis.dataflow import DataFlowAnalyzer
from securecode.config import ScanConfig
from securecode.core.finding import (
    ScanMetadata,
    ScanResult,
    ScanSummary,
    Severity,
    Vulnerability,
)
from securecode.core.scanner import ScannerRegistry

# Import scanners to trigger registration
from securecode.scanners.csharp import CSharpScanner  # noqa: F401
from securecode.scanners.typescript import TypeScriptScanner  # noqa: F401

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates security scanning across multiple languages."""

    def __init__(self, config: ScanConfig) -> None:
        """Initialize the orchestrator.

        Args:
            config: Scan configuration
        """
        self.config = config
        self._files_scanned = 0
        self._files_with_errors = 0
        self._source_map: dict[Path, str] = {}  # Store source for deep analysis
        self._deep_analysis_stats = None

    def scan(
        self,
        path: Path,
        progress_callback: Callable[[str], None] | None = None,
    ) -> ScanResult:
        """Scan a directory or file for security vulnerabilities.

        Args:
            path: Path to scan (directory or file)
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult containing all findings
        """
        start_time = time.time()
        scan_id = f"scan-{uuid4().hex[:8]}"

        if progress_callback:
            progress_callback("Discovering files...")

        # Discover files to scan
        if path.is_file():
            files = [path] if self._should_scan_file(path) else []
            scan_root = path.parent
        else:
            files = self._discover_files(path)
            scan_root = path

        logger.info(f"Found {len(files)} files to scan")

        if progress_callback:
            progress_callback(f"Scanning {len(files)} files...")

        # Scan files
        vulnerabilities: list[Vulnerability] = []
        languages_found: set[str] = set()

        for file_path in files:
            try:
                file_vulns = self._scan_file(file_path, scan_root)
                vulnerabilities.extend(file_vulns)
                self._files_scanned += 1

                # Track languages
                scanner = ScannerRegistry.get_scanner_for_file(file_path)
                if scanner:
                    languages_found.add(scanner.language_id)

            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")
                self._files_with_errors += 1

        # Apply severity filter
        if self.config.severity_threshold != Severity.INFO:
            vulnerabilities = [
                v for v in vulnerabilities
                if v.severity >= self.config.severity_threshold
            ]

        # Deep analysis post-processing
        if self.config.enable_deep_analysis and vulnerabilities:
            if progress_callback:
                progress_callback(f"Performing deep analysis on {len(vulnerabilities)} findings...")

            analyzer = DataFlowAnalyzer(self.config)
            vulnerabilities, self._deep_analysis_stats = analyzer.analyze(
                vulnerabilities, self._source_map
            )
            logger.info(
                f"Deep analysis complete: {self._deep_analysis_stats.total_analyzed} analyzed, "
                f"{self._deep_analysis_stats.safe_filtered} filtered"
            )

        # Calculate duration
        duration = time.time() - start_time

        # Build result
        metadata = ScanMetadata(
            scan_id=scan_id,
            timestamp=datetime.utcnow(),
            scanner_version=__version__,
            target_directory=scan_root,
            files_scanned=self._files_scanned,
            files_with_errors=self._files_with_errors,
            scan_duration_seconds=round(duration, 2),
            languages_scanned=sorted(languages_found),
            excluded_directories=self.config.exclude_dirs,
        )

        summary = self._build_summary(vulnerabilities)

        return ScanResult(
            metadata=metadata,
            summary=summary,
            vulnerabilities=vulnerabilities,
        )

    def scan_single_file(self, file_path: Path) -> list[Vulnerability]:
        """Scan a single file for vulnerabilities.

        Args:
            file_path: Path to the file

        Returns:
            List of vulnerabilities found
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        return self._scan_file(file_path, file_path.parent)

    def _discover_files(self, directory: Path) -> list[Path]:
        """Discover all scannable files in a directory."""
        files: list[Path] = []
        supported_extensions = ScannerRegistry.get_supported_extensions()

        # Filter by language if specified
        if self.config.languages:
            language_extensions: set[str] = set()
            for lang in self.config.languages:
                lang = lang.lower().strip()
                if lang in ("ts", "typescript", "js", "javascript"):
                    language_extensions.update([".ts", ".tsx", ".js", ".jsx"])
                elif lang in ("cs", "csharp", "c#"):
                    language_extensions.add(".cs")
            supported_extensions = language_extensions

        for ext in supported_extensions:
            for file_path in directory.rglob(f"*{ext}"):
                if self._should_scan_file(file_path):
                    files.append(file_path)

        return sorted(files)

    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if a file should be scanned."""
        # Check extension
        if not ScannerRegistry.get_scanner_for_file(file_path):
            return False

        # Check excluded directories
        parts = file_path.parts
        for exclude_dir in self.config.exclude_dirs:
            if exclude_dir in parts:
                return False

        # Check file size
        try:
            size_mb = file_path.stat().st_size / (1024 * 1024)
            if size_mb > self.config.max_file_size_mb:
                logger.debug(f"Skipping large file: {file_path} ({size_mb:.1f}MB)")
                return False
        except OSError:
            return False

        # Check exclude patterns
        for pattern in self.config.exclude_patterns:
            if file_path.match(pattern):
                return False

        return True

    def _scan_file(self, file_path: Path, scan_root: Path) -> list[Vulnerability]:
        """Scan a single file using the appropriate scanner."""
        scanner = ScannerRegistry.get_scanner_for_file(file_path)
        if scanner is None:
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            # Store source content for deep analysis
            self._source_map[file_path] = content
            return scanner.scan_file(file_path, content, scan_root)
        except Exception as e:
            logger.error(f"Error reading/scanning {file_path}: {e}")
            return []

    def _build_summary(self, vulnerabilities: list[Vulnerability]) -> ScanSummary:
        """Build summary statistics from vulnerabilities."""
        by_severity: Counter[str] = Counter()
        by_type: Counter[str] = Counter()
        by_language: Counter[str] = Counter()
        by_file: Counter[str] = Counter()

        for vuln in vulnerabilities:
            by_severity[vuln.severity.value] += 1
            by_type[vuln.vulnerability_type.value] += 1
            by_language[vuln.language] += 1
            by_file[str(vuln.relative_path)] += 1

        # Get top vulnerable files
        top_files = [
            {"file": file, "count": count}
            for file, count in by_file.most_common(10)
        ]

        return ScanSummary(
            total_vulnerabilities=len(vulnerabilities),
            by_severity=dict(by_severity),
            by_type=dict(by_type),
            by_language=dict(by_language),
            top_vulnerable_files=top_files,
        )

    def scan_parallel(
        self,
        path: Path,
        progress_callback: Callable[[str], None] | None = None,
    ) -> ScanResult:
        """Scan using parallel processing for large codebases.

        Args:
            path: Path to scan
            progress_callback: Optional callback for progress updates

        Returns:
            ScanResult containing all findings
        """
        # For now, fall back to sequential scanning
        # Parallel scanning would require careful handling of
        # tree-sitter parser state and process pools
        return self.scan(path, progress_callback)
