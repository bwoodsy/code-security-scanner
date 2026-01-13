"""TypeScript/JavaScript security scanner."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from securecode.core.scanner import BaseScanner, ScannerRegistry
from securecode.parsers.typescript import JavaScriptParser, TSXParser, TypeScriptParser

# Import rules to trigger registration
from securecode.scanners.typescript.rules import (  # noqa: F401
    CommandInjectionRule,
    HardcodedSecretsRule,
    SQLInjectionRule,
    XSSRule,
)

if TYPE_CHECKING:
    from tree_sitter import Tree

logger = logging.getLogger(__name__)


@ScannerRegistry.register
class TypeScriptScanner(BaseScanner):
    """Security scanner for TypeScript and JavaScript files."""

    def __init__(self) -> None:
        """Initialize the TypeScript scanner."""
        self._ts_parser = TypeScriptParser()
        self._tsx_parser = TSXParser()
        self._js_parser = JavaScriptParser()

    @property
    def language_id(self) -> str:
        """Unique identifier for this language."""
        return "typescript"

    @property
    def file_extensions(self) -> list[str]:
        """List of supported file extensions."""
        return [".ts", ".tsx", ".js", ".jsx"]

    def parse_file(self, content: str) -> Tree | None:
        """Parse TypeScript/JavaScript source code."""
        # Try TypeScript parser first (handles most cases)
        tree = self._ts_parser.parse(content)
        if tree and not tree.root_node.has_error:
            return tree

        # Fall back to TSX for JSX content
        tree = self._tsx_parser.parse(content)
        if tree and not tree.root_node.has_error:
            return tree

        # Fall back to JavaScript
        tree = self._js_parser.parse(content)
        return tree

    def _get_parser_for_extension(self, file_path: Path) -> TypeScriptParser | TSXParser | JavaScriptParser:
        """Get the appropriate parser for a file extension."""
        ext = file_path.suffix.lower()
        if ext == ".tsx":
            return self._tsx_parser
        elif ext == ".jsx":
            return self._tsx_parser  # TSX parser handles JSX
        elif ext == ".js":
            return self._js_parser
        else:
            return self._ts_parser
