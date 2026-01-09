"""Base scanner interface for language-specific security scanners."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from securecode.core.finding import Confidence, Severity, Vulnerability, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, RuleRegistry

if TYPE_CHECKING:
    from tree_sitter import Tree

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Base class for all language scanners.

    Extend this class to add support for new programming languages.
    Each scanner is responsible for:
    - Parsing files using tree-sitter
    - Running registered rules against the AST
    - Converting rule matches to Vulnerability objects
    """

    @property
    @abstractmethod
    def language_id(self) -> str:
        """Unique identifier for this language (e.g., 'typescript', 'csharp')."""

    @property
    @abstractmethod
    def file_extensions(self) -> list[str]:
        """List of supported file extensions (e.g., ['.ts', '.tsx'])."""

    @abstractmethod
    def parse_file(self, content: str) -> Tree | None:
        """Parse source code into a tree-sitter AST.

        Args:
            content: Source code to parse

        Returns:
            Parsed AST or None if parsing failed
        """

    def get_rules(self) -> list[Rule]:
        """Get all registered rules for this scanner's language."""
        rule_classes = RuleRegistry.get_rules(self.language_id)
        return [cls() for cls in rule_classes]

    def supports_file(self, file_path: Path) -> bool:
        """Check if this scanner supports the given file."""
        return file_path.suffix.lower() in self.file_extensions

    def scan_file(
        self,
        file_path: Path,
        content: str,
        scan_root: Path,
    ) -> list[Vulnerability]:
        """Scan a single file for vulnerabilities.

        Args:
            file_path: Absolute path to the file
            content: File contents
            scan_root: Root directory of the scan (for relative paths)

        Returns:
            List of found vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        # Parse the file
        tree = self.parse_file(content)
        if tree is None:
            logger.warning(f"Failed to parse {file_path}")
            return vulnerabilities

        # Get relative path
        try:
            relative_path = file_path.relative_to(scan_root)
        except ValueError:
            relative_path = file_path

        # Run all rules
        rules = self.get_rules()
        for rule in rules:
            try:
                matches = rule.detect(tree, content, str(file_path))
                for match in matches:
                    vuln = self._match_to_vulnerability(
                        match=match,
                        rule=rule,
                        file_path=file_path,
                        relative_path=relative_path,
                        content=content,
                    )
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.error(f"Error running rule {rule.rule_id} on {file_path}: {e}")

        return vulnerabilities

    def _match_to_vulnerability(
        self,
        match: RuleMatch,
        rule: Rule,
        file_path: Path,
        relative_path: Path,
        content: str,
    ) -> Vulnerability:
        """Convert a RuleMatch to a Vulnerability object."""
        # Get code snippet with context
        code_snippet = self._get_code_snippet(content, match.line, context_lines=2)

        return Vulnerability(
            id=f"vuln-{uuid4().hex[:8]}",
            rule_id=rule.rule_id,
            file_path=file_path,
            relative_path=relative_path,
            line=match.line,
            column=match.column,
            end_line=match.end_line,
            end_column=match.end_column,
            code_snippet=code_snippet,
            matched_code=match.matched_code,
            vulnerability_type=rule.vulnerability_type,
            severity=rule.severity,
            confidence=match.confidence_override or rule.confidence,
            title=rule.title,
            description=rule.description,
            remediation=rule.remediation,
            cwe_id=rule.cwe_id,
            owasp_category=rule.owasp_category,
            language=self.language_id,
            metadata=match.context,
        )

    def _get_code_snippet(self, content: str, line: int, context_lines: int = 2) -> str:
        """Extract a code snippet with context lines."""
        lines = content.splitlines()
        start = max(0, line - context_lines - 1)
        end = min(len(lines), line + context_lines)

        snippet_lines = []
        for i in range(start, end):
            line_num = i + 1
            prefix = "→ " if line_num == line else "  "
            snippet_lines.append(f"{line_num:4d} {prefix}{lines[i]}")

        return "\n".join(snippet_lines)

    def scan_directory(
        self,
        directory: Path,
        exclude_patterns: list[str] | None = None,
    ) -> list[Vulnerability]:
        """Scan all supported files in a directory.

        Args:
            directory: Directory to scan
            exclude_patterns: Glob patterns for directories/files to exclude

        Returns:
            List of found vulnerabilities
        """
        if exclude_patterns is None:
            exclude_patterns = []

        vulnerabilities: list[Vulnerability] = []

        for file_path in self._discover_files(directory, exclude_patterns):
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                file_vulns = self.scan_file(file_path, content, directory)
                vulnerabilities.extend(file_vulns)
            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")

        return vulnerabilities

    def _discover_files(
        self,
        directory: Path,
        exclude_patterns: list[str],
    ) -> list[Path]:
        """Discover all scannable files in a directory."""
        files: list[Path] = []
        default_excludes = {
            "node_modules",
            ".git",
            "__pycache__",
            "dist",
            "build",
            "bin",
            "obj",
            ".venv",
            "venv",
        }

        for ext in self.file_extensions:
            for file_path in directory.rglob(f"*{ext}"):
                # Check if file is in excluded directory
                parts = file_path.relative_to(directory).parts
                if any(part in default_excludes for part in parts):
                    continue
                if any(file_path.match(pattern) for pattern in exclude_patterns):
                    continue
                files.append(file_path)

        return files


class ScannerRegistry:
    """Registry for managing language scanners."""

    _scanners: dict[str, type[BaseScanner]] = {}

    @classmethod
    def register(cls, scanner_class: type[BaseScanner]) -> type[BaseScanner]:
        """Register a scanner class."""
        # Create instance to get language_id
        instance = scanner_class()
        cls._scanners[instance.language_id] = scanner_class
        return scanner_class

    @classmethod
    def get_scanner(cls, language: str) -> BaseScanner | None:
        """Get a scanner instance for a language."""
        scanner_class = cls._scanners.get(language)
        if scanner_class:
            return scanner_class()
        return None

    @classmethod
    def get_scanner_for_file(cls, file_path: Path) -> BaseScanner | None:
        """Get the appropriate scanner for a file based on extension."""
        for scanner_class in cls._scanners.values():
            scanner = scanner_class()
            if scanner.supports_file(file_path):
                return scanner
        return None

    @classmethod
    def get_all_scanners(cls) -> list[BaseScanner]:
        """Get instances of all registered scanners."""
        return [scanner_class() for scanner_class in cls._scanners.values()]

    @classmethod
    def get_supported_extensions(cls) -> set[str]:
        """Get all file extensions supported by registered scanners."""
        extensions: set[str] = set()
        for scanner_class in cls._scanners.values():
            scanner = scanner_class()
            extensions.update(scanner.file_extensions)
        return extensions
