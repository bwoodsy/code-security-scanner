"""Data models for deep analysis results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AnalysisVerdict(str, Enum):
    """Verdict from data flow analysis."""

    CONFIRMED = "CONFIRMED"  # Source is user input with no sanitization
    LIKELY = "LIKELY"  # Source probably user input, unclear sanitization
    POSSIBLE = "POSSIBLE"  # Source could be user input, path unclear
    UNLIKELY = "UNLIKELY"  # Source appears to be constant/safe
    SAFE = "SAFE"  # Source is definitely not user input or is sanitized


@dataclass
class DataFlowResult:
    """Result of data flow analysis for a single vulnerability."""

    # Analysis outcome
    performed: bool = False
    verdict: AnalysisVerdict = AnalysisVerdict.POSSIBLE

    # Source tracking
    source_found: bool = False
    source_type: str | None = None
    source_line: int | None = None

    # Sink info
    sink_variable: str | None = None

    # Sanitization detection
    sanitization_found: bool = False
    sanitizer_type: str | None = None
    sanitizer_line: int | None = None

    # Confidence adjustment (-1.0 to +1.0)
    confidence_adjustment: float = 0.0

    # Trace information
    trace_path: list[str] = field(default_factory=list)
    trace_depth: int = 0

    # Human-readable explanation
    analysis_notes: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "performed": self.performed,
            "verdict": self.verdict.value,
            "source_found": self.source_found,
            "source_type": self.source_type,
            "source_line": self.source_line,
            "sink_variable": self.sink_variable,
            "sanitization_found": self.sanitization_found,
            "sanitizer_type": self.sanitizer_type,
            "sanitizer_line": self.sanitizer_line,
            "confidence_adjustment": self.confidence_adjustment,
            "trace_path": self.trace_path,
            "trace_depth": self.trace_depth,
            "analysis_notes": self.analysis_notes,
            "recommendation": self.recommendation,
        }


@dataclass
class DeepAnalysisStats:
    """Statistics from deep analysis phase."""

    total_analyzed: int = 0
    confirmed_vulnerabilities: int = 0
    likely_vulnerabilities: int = 0
    possible_vulnerabilities: int = 0
    unlikely_vulnerabilities: int = 0
    safe_filtered: int = 0

    # By verdict
    verdicts: dict[str, int] = field(default_factory=dict)

    # Performance
    analysis_time_seconds: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_analyzed": self.total_analyzed,
            "confirmed_vulnerabilities": self.confirmed_vulnerabilities,
            "likely_vulnerabilities": self.likely_vulnerabilities,
            "possible_vulnerabilities": self.possible_vulnerabilities,
            "unlikely_vulnerabilities": self.unlikely_vulnerabilities,
            "safe_filtered": self.safe_filtered,
            "verdicts": self.verdicts,
            "analysis_time_seconds": round(self.analysis_time_seconds, 2),
        }
