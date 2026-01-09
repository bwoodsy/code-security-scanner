"""TypeScript/JavaScript parser using tree-sitter."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from securecode.parsers.base import BaseParser

if TYPE_CHECKING:
    from tree_sitter import Parser

logger = logging.getLogger(__name__)


class TypeScriptParser(BaseParser):
    """Parser for TypeScript and JavaScript files."""

    @property
    def language_name(self) -> str:
        """The tree-sitter language name."""
        return "typescript"

    def _create_parser(self) -> Parser:
        """Create the TypeScript parser."""
        try:
            from tree_sitter import Parser
            from tree_sitter_language_pack import get_language

            parser = Parser()
            language = get_language("typescript")
            parser.language = language
            return parser
        except ImportError as e:
            logger.error(f"Failed to import tree-sitter dependencies: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to create TypeScript parser: {e}")
            raise


class TSXParser(BaseParser):
    """Parser for TSX (TypeScript with JSX) files."""

    @property
    def language_name(self) -> str:
        """The tree-sitter language name."""
        return "tsx"

    def _create_parser(self) -> Parser:
        """Create the TSX parser."""
        try:
            from tree_sitter import Parser
            from tree_sitter_language_pack import get_language

            parser = Parser()
            language = get_language("tsx")
            parser.language = language
            return parser
        except ImportError as e:
            logger.error(f"Failed to import tree-sitter dependencies: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to create TSX parser: {e}")
            raise


class JavaScriptParser(BaseParser):
    """Parser for JavaScript files."""

    @property
    def language_name(self) -> str:
        """The tree-sitter language name."""
        return "javascript"

    def _create_parser(self) -> Parser:
        """Create the JavaScript parser."""
        try:
            from tree_sitter import Parser
            from tree_sitter_language_pack import get_language

            parser = Parser()
            language = get_language("javascript")
            parser.language = language
            return parser
        except ImportError as e:
            logger.error(f"Failed to import tree-sitter dependencies: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to create JavaScript parser: {e}")
            raise
