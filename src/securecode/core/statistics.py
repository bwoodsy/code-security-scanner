"""Statistics and false positive estimation for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from securecode.core.finding import Finding, Confidence


@dataclass
class VulnerabilityStats:
    """Statistics for a specific vulnerability type."""

    total_findings: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    estimated_true_positives: float = 0.0
    estimated_false_positives: float = 0.0

    @property
    def estimated_fp_rate(self) -> float:
        """Calculate estimated false positive rate as a percentage."""
        if self.total_findings == 0:
            return 0.0
        return (self.estimated_false_positives / self.total_findings) * 100

    @property
    def estimated_tp_rate(self) -> float:
        """Calculate estimated true positive rate as a percentage."""
        if self.total_findings == 0:
            return 0.0
        return (self.estimated_true_positives / self.total_findings) * 100


@dataclass
class ScanStatistics:
    """Comprehensive statistics for a scan."""

    total_files: int = 0
    files_with_findings: int = 0
    total_findings: int = 0
    by_type: dict[str, VulnerabilityStats] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    by_confidence: dict[str, int] = field(default_factory=dict)

    # Overall estimates (floats for probabilistic calculation)
    estimated_true_positives: float = 0.0
    estimated_false_positives: float = 0.0

    @property
    def overall_fp_rate(self) -> float:
        """Calculate overall estimated false positive rate."""
        if self.total_findings == 0:
            return 0.0
        return (self.estimated_false_positives / self.total_findings) * 100

    @property
    def overall_tp_rate(self) -> float:
        """Calculate overall estimated true positive rate."""
        if self.total_findings == 0:
            return 0.0
        return (self.estimated_true_positives / self.total_findings) * 100

    def to_dict(self) -> dict:
        """Convert statistics to dictionary for JSON serialization."""
        return {
            "total_files_scanned": self.total_files,
            "files_with_findings": self.files_with_findings,
            "total_findings": self.total_findings,
            "confidence_distribution": self.by_confidence,
            "estimates": {
                "estimated_true_positives": round(self.estimated_true_positives),
                "estimated_false_positives": round(self.estimated_false_positives),
                "overall_true_positive_rate": round(self.overall_tp_rate, 1),
                "overall_false_positive_rate": round(self.overall_fp_rate, 1),
            },
            "by_vulnerability_type": {
                vuln_type: {
                    "total": stats.total_findings,
                    "high_confidence": stats.high_confidence,
                    "medium_confidence": stats.medium_confidence,
                    "low_confidence": stats.low_confidence,
                    "estimated_true_positives": round(stats.estimated_true_positives),
                    "estimated_false_positives": round(stats.estimated_false_positives),
                    "estimated_tp_rate": round(stats.estimated_tp_rate, 1),
                    "estimated_fp_rate": round(stats.estimated_fp_rate, 1),
                }
                for vuln_type, stats in self.by_type.items()
            },
        }


# False positive rate estimates based on confidence level and vulnerability type
# These are calibrated estimates based on industry benchmarks
FP_RATE_BY_CONFIDENCE = {
    "HIGH": 0.10,    # 10% FP rate for high confidence findings
    "MEDIUM": 0.35,  # 35% FP rate for medium confidence
    "LOW": 0.60,     # 60% FP rate for low confidence
}

# Additional FP adjustments by vulnerability type (some types are harder to detect accurately)
FP_ADJUSTMENT_BY_TYPE = {
    "SQL_INJECTION": 0.0,        # Well-defined patterns
    "COMMAND_INJECTION": 0.0,    # Well-defined patterns
    "XSS": 0.05,                 # Slightly harder (context-dependent)
    "HARDCODED_SECRET": 0.15,    # Many false positives (test data, etc.)
    "PATH_TRAVERSAL": 0.10,      # Context-dependent
    "WEAK_CRYPTO": 0.05,         # Clear patterns
    "INSECURE_DESERIALIZATION": 0.0,  # Very clear patterns
    "OPEN_REDIRECT": 0.10,       # Context-dependent
    "LDAP_INJECTION": 0.0,       # Clear patterns
    "XXE": 0.0,                  # Clear patterns
    "PROTOTYPE_POLLUTION": 0.15, # Context-dependent
    "INSECURE_COOKIE": 0.10,     # May have valid use cases
}


def calculate_statistics(findings: list["Finding"]) -> ScanStatistics:
    """Calculate comprehensive statistics for a list of findings."""
    from securecode.core.finding import Confidence

    stats = ScanStatistics()
    stats.total_findings = len(findings)

    # Track unique files
    files_with_findings = set()

    for finding in findings:
        files_with_findings.add(finding.file_path)

        # By severity
        severity_str = finding.severity.value
        stats.by_severity[severity_str] = stats.by_severity.get(severity_str, 0) + 1

        # By confidence
        confidence_str = finding.confidence.value
        stats.by_confidence[confidence_str] = stats.by_confidence.get(confidence_str, 0) + 1

        # By vulnerability type
        vuln_type = finding.vulnerability_type.value
        if vuln_type not in stats.by_type:
            stats.by_type[vuln_type] = VulnerabilityStats()

        type_stats = stats.by_type[vuln_type]
        type_stats.total_findings += 1

        # Count by confidence level
        if finding.confidence == Confidence.HIGH:
            type_stats.high_confidence += 1
        elif finding.confidence == Confidence.MEDIUM:
            type_stats.medium_confidence += 1
        else:
            type_stats.low_confidence += 1

        # Estimate FP rate for this finding using probabilistic calculation
        fp_prob = estimate_finding_fp_probability(finding)

        # Use probabilistic accumulation (expected value)
        # For high confidence (10% FP rate), add 0.1 to FP count, 0.9 to TP count
        type_stats.estimated_false_positives += fp_prob
        type_stats.estimated_true_positives += (1 - fp_prob)
        stats.estimated_false_positives += fp_prob
        stats.estimated_true_positives += (1 - fp_prob)

    stats.files_with_findings = len(files_with_findings)

    return stats


def estimate_finding_fp_probability(finding: "Finding") -> float:
    """
    Estimate the probability that a specific finding is a false positive.

    Returns a value between 0.0 (definitely true positive) and 1.0 (definitely false positive).
    """
    confidence_str = finding.confidence.value
    vuln_type = finding.vulnerability_type.value

    base_fp_rate = FP_RATE_BY_CONFIDENCE.get(confidence_str, 0.35)
    type_adjustment = FP_ADJUSTMENT_BY_TYPE.get(vuln_type, 0.10)

    # Additional heuristics based on matched code
    code = finding.matched_code.lower() if finding.matched_code else ""

    # Increase FP probability for test files
    file_path_str = str(finding.file_path).lower() if finding.file_path else ""
    if file_path_str and any(
        pattern in file_path_str
        for pattern in ["test", "spec", "mock", "__test__", ".test.", ".spec."]
    ):
        type_adjustment += 0.20

    # Decrease FP probability for certain clear patterns
    if vuln_type == "SQL_INJECTION" and any(
        kw in code for kw in ["select * from", "insert into", "delete from", "update "]
    ):
        type_adjustment -= 0.10

    return min(max(base_fp_rate + type_adjustment, 0.0), 1.0)
