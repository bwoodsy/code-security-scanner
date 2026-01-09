"""SecureCode-AI: Static code security scanner for TypeScript and C# codebases."""

__version__ = "1.0.0"
__author__ = "SecureCode-AI Team"

from securecode.core.finding import Confidence, Severity, Vulnerability, VulnerabilityType

__all__ = [
    "__version__",
    "Vulnerability",
    "VulnerabilityType",
    "Severity",
    "Confidence",
]
