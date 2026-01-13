"""TypeScript security rules."""

from securecode.scanners.typescript.rules.injection import (
    CommandInjectionRule,
    SQLInjectionRule,
)
from securecode.scanners.typescript.rules.secrets import HardcodedSecretsRule
from securecode.scanners.typescript.rules.ssrf import SSRFRule
from securecode.scanners.typescript.rules.xss import XSSRule

__all__ = [
    "XSSRule",
    "CommandInjectionRule",
    "SQLInjectionRule",
    "HardcodedSecretsRule",
    "SSRFRule",
]
