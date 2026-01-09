"""Base parser interface for language parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Parser, Tree


class BaseParser(ABC):
    """Base class for language parsers using tree-sitter."""

    def __init__(self) -> None:
        """Initialize the parser."""
        self._parser: Parser | None = None

    @property
    @abstractmethod
    def language_name(self) -> str:
        """The tree-sitter language name (e.g., 'typescript', 'c_sharp')."""

    @abstractmethod
    def _create_parser(self) -> Parser:
        """Create and configure the tree-sitter parser."""

    @property
    def parser(self) -> Parser:
        """Get or create the parser instance."""
        if self._parser is None:
            self._parser = self._create_parser()
        return self._parser

    def parse(self, source: str) -> Tree | None:
        """Parse source code into an AST.

        Args:
            source: Source code to parse

        Returns:
            Parsed AST tree or None if parsing failed
        """
        try:
            tree = self.parser.parse(source.encode("utf-8"))
            return tree
        except Exception:
            return None

    def parse_bytes(self, source: bytes) -> Tree | None:
        """Parse source code bytes into an AST.

        Args:
            source: Source code bytes to parse

        Returns:
            Parsed AST tree or None if parsing failed
        """
        try:
            tree = self.parser.parse(source)
            return tree
        except Exception:
            return None
