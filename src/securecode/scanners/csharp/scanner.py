"""C# security scanner."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from securecode.core.scanner import BaseScanner, ScannerRegistry
from securecode.parsers.csharp import CSharpParser

# Import rules to trigger registration
from securecode.scanners.csharp.rules import (  # noqa: F401
    CommandInjectionRule,
    HardcodedSecretsRule,
    InsecureDeserializationRule,
    SQLInjectionRule,
    SSRFRule,
    WeakCryptoRule,
)

if TYPE_CHECKING:
    from tree_sitter import Tree

logger = logging.getLogger(__name__)


@ScannerRegistry.register
class CSharpScanner(BaseScanner):
    """Security scanner for C# files."""

    def __init__(self) -> None:
        """Initialize the C# scanner."""
        self._parser = CSharpParser()

    @property
    def language_id(self) -> str:
        """Unique identifier for this language."""
        return "csharp"

    @property
    def file_extensions(self) -> list[str]:
        """List of supported file extensions."""
        return [".cs"]

    def parse_file(self, content: str) -> Tree | None:
        """Parse C# source code."""
        return self._parser.parse(content)
