"""Data models for vulnerability findings."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for vulnerabilities."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def _order_index(self) -> int:
        """Get the order index for comparison."""
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return order.index(self.value)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._order_index < other._order_index

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._order_index <= other._order_index

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._order_index > other._order_index

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._order_index >= other._order_index


class Confidence(str, Enum):
    """Confidence levels for vulnerability detection."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VulnerabilityType(str, Enum):
    """Types of security vulnerabilities."""

    # Injection
    XSS = "XSS"
    SQL_INJECTION = "SQL_INJECTION"
    NOSQL_INJECTION = "NOSQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    CODE_INJECTION = "CODE_INJECTION"
    LDAP_INJECTION = "LDAP_INJECTION"
    XPATH_INJECTION = "XPATH_INJECTION"

    # Data Exposure
    HARDCODED_SECRET = "HARDCODED_SECRET"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    SENSITIVE_DATA_LOGGING = "SENSITIVE_DATA_LOGGING"

    # Cryptography
    WEAK_CRYPTO = "WEAK_CRYPTO"
    INSECURE_RANDOM = "INSECURE_RANDOM"

    # Deserialization
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"

    # File System
    PATH_TRAVERSAL = "PATH_TRAVERSAL"

    # Network
    SSRF = "SSRF"
    OPEN_REDIRECT = "OPEN_REDIRECT"

    # Web Security
    CSRF = "CSRF"
    CORS_MISCONFIGURATION = "CORS_MISCONFIGURATION"
    INSECURE_COOKIE = "INSECURE_COOKIE"
    MISSING_AUTH = "MISSING_AUTH"

    # Other
    XXE = "XXE"
    PROTOTYPE_POLLUTION = "PROTOTYPE_POLLUTION"
    REGEX_DOS = "REGEX_DOS"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    INSECURE_DEPENDENCY = "INSECURE_DEPENDENCY"

    # Generic
    OTHER = "OTHER"


class Vulnerability(BaseModel):
    """Represents a detected security vulnerability."""

    # Identification
    id: str = Field(description="Unique identifier for this finding")
    rule_id: str = Field(description="ID of the rule that detected this vulnerability")

    # Location
    file_path: Path = Field(description="Absolute path to the file")
    relative_path: Path = Field(description="Path relative to scan root")
    line: int = Field(ge=1, description="Line number (1-indexed)")
    column: int = Field(ge=1, description="Column number (1-indexed)")
    end_line: int | None = Field(default=None, description="End line number if span")
    end_column: int | None = Field(default=None, description="End column number if span")

    # Code context
    code_snippet: str = Field(description="Code snippet with context (typically 5 lines)")
    matched_code: str = Field(description="The specific code that matched the rule")

    # Classification
    vulnerability_type: VulnerabilityType = Field(description="Type of vulnerability")
    severity: Severity = Field(description="Severity level")
    confidence: Confidence = Field(description="Detection confidence level")

    # Description
    title: str = Field(description="Short title for the vulnerability")
    description: str = Field(description="Detailed description of why this is vulnerable")
    remediation: str = Field(description="Suggested fix or remediation steps")

    # Metadata
    cwe_id: str | None = Field(default=None, description="CWE identifier (e.g., CWE-79)")
    owasp_category: str | None = Field(default=None, description="OWASP category (e.g., A03:2021)")
    language: str = Field(description="Programming language (typescript, csharp)")

    # Additional context
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        """Pydantic configuration."""

        frozen = True
        json_encoders = {Path: str}


class ScanMetadata(BaseModel):
    """Metadata about a scan run."""

    scan_id: str = Field(description="Unique identifier for this scan")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    scanner_version: str = Field(description="Version of SecureCode-AI")
    target_directory: Path = Field(description="Root directory that was scanned")
    files_scanned: int = Field(ge=0, description="Number of files scanned")
    files_with_errors: int = Field(ge=0, default=0, description="Files with parse errors")
    scan_duration_seconds: float = Field(ge=0, description="Total scan duration")
    languages_scanned: list[str] = Field(default_factory=list)
    excluded_directories: list[str] = Field(default_factory=list)

    class Config:
        """Pydantic configuration."""

        json_encoders = {Path: str, datetime: lambda v: v.isoformat()}


class ScanSummary(BaseModel):
    """Summary statistics for a scan."""

    total_vulnerabilities: int = Field(ge=0)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)
    by_language: dict[str, int] = Field(default_factory=dict)
    top_vulnerable_files: list[dict[str, Any]] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Complete result of a security scan."""

    schema_version: str = Field(default="1.0")
    metadata: ScanMetadata
    summary: ScanSummary
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)

    class Config:
        """Pydantic configuration."""

        json_encoders = {Path: str, datetime: lambda v: v.isoformat()}

    def filter_by_severity(self, min_severity: Severity) -> list[Vulnerability]:
        """Filter vulnerabilities by minimum severity."""
        return [v for v in self.vulnerabilities if v.severity >= min_severity]

    def filter_by_type(self, vuln_type: VulnerabilityType) -> list[Vulnerability]:
        """Filter vulnerabilities by type."""
        return [v for v in self.vulnerabilities if v.vulnerability_type == vuln_type]

    def get_vulnerabilities_by_file(self) -> dict[Path, list[Vulnerability]]:
        """Group vulnerabilities by file path."""
        result: dict[Path, list[Vulnerability]] = {}
        for vuln in self.vulnerabilities:
            if vuln.relative_path not in result:
                result[vuln.relative_path] = []
            result[vuln.relative_path].append(vuln)
        return result
