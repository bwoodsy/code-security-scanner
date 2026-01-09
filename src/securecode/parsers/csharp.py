"""C# parser using tree-sitter."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from securecode.parsers.base import BaseParser

if TYPE_CHECKING:
    from tree_sitter import Parser

logger = logging.getLogger(__name__)


class CSharpParser(BaseParser):
    """Parser for C# files."""

    @property
    def language_name(self) -> str:
        """The tree-sitter language name."""
        return "csharp"

    def _create_parser(self) -> Parser:
        """Create the C# parser."""
        try:
            from tree_sitter import Parser
            from tree_sitter_language_pack import get_language

            parser = Parser()
            language = get_language("csharp")
            parser.language = language
            return parser
        except ImportError as e:
            logger.error(f"Failed to import tree-sitter dependencies: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to create C# parser: {e}")
            raise
