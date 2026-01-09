"""Base classes for security detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from securecode.core.finding import Confidence, Severity, VulnerabilityType

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@dataclass
class RuleMatch:
    """Represents a match found by a rule."""

    line: int
    column: int
    end_line: int | None = None
    end_column: int | None = None
    matched_code: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    confidence_override: Confidence | None = None  # Allow rules to override confidence per-match


class Rule(ABC):
    """Base class for vulnerability detection rules.

    Extend this class to create custom security rules. Each rule
    should detect a specific vulnerability pattern.
    """

    # Rule identification
    rule_id: str
    language: str

    # Classification
    vulnerability_type: VulnerabilityType
    severity: Severity
    confidence: Confidence

    # Metadata
    cwe_id: str | None = None
    owasp_category: str | None = None

    # Documentation
    title: str
    description: str
    remediation: str

    @abstractmethod
    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect vulnerabilities in the given AST.

        Args:
            tree: The parsed AST from tree-sitter
            source: The original source code
            file_path: Path to the file being scanned

        Returns:
            List of RuleMatch objects representing found vulnerabilities
        """

    def _get_node_text(self, node: Node, source: str) -> str:
        """Extract text from a tree-sitter node."""
        return source[node.start_byte : node.end_byte]

    def _get_line_context(self, source: str, line: int, context_lines: int = 2) -> str:
        """Get source code context around a specific line."""
        lines = source.splitlines()
        start = max(0, line - context_lines - 1)
        end = min(len(lines), line + context_lines)
        return "\n".join(lines[start:end])

    def _find_nodes_by_type(self, node: Node, node_type: str) -> list[Node]:
        """Recursively find all nodes of a specific type."""
        result: list[Node] = []
        if node.type == node_type:
            result.append(node)
        for child in node.children:
            result.extend(self._find_nodes_by_type(child, node_type))
        return result

    def _find_nodes_by_types(self, node: Node, node_types: set[str]) -> list[Node]:
        """Recursively find all nodes matching any of the given types."""
        result: list[Node] = []
        if node.type in node_types:
            result.append(node)
        for child in node.children:
            result.extend(self._find_nodes_by_types(child, node_types))
        return result

    def _get_ancestor_of_type(self, node: Node, node_type: str) -> Node | None:
        """Find the nearest ancestor of a specific type."""
        current = node.parent
        while current is not None:
            if current.type == node_type:
                return current
            current = current.parent
        return None


class RuleRegistry:
    """Registry for auto-discovering and managing security rules."""

    _rules: dict[str, list[type[Rule]]] = {}

    @classmethod
    def register(cls, rule_class: type[Rule]) -> type[Rule]:
        """Register a rule class (used as decorator).

        Usage:
            @RuleRegistry.register
            class MyRule(Rule):
                ...
        """
        language = rule_class.language
        if language not in cls._rules:
            cls._rules[language] = []
        cls._rules[language].append(rule_class)
        return rule_class

    @classmethod
    def get_rules(cls, language: str) -> list[type[Rule]]:
        """Get all registered rules for a language."""
        return cls._rules.get(language, [])

    @classmethod
    def get_all_rules(cls) -> dict[str, list[type[Rule]]]:
        """Get all registered rules grouped by language."""
        return cls._rules.copy()

    @classmethod
    def clear(cls) -> None:
        """Clear all registered rules (useful for testing)."""
        cls._rules.clear()


def register_rule(cls: type[Rule]) -> type[Rule]:
    """Decorator to register a rule with the RuleRegistry.

    Usage:
        @register_rule
        class MyRule(Rule):
            ...
    """
    return RuleRegistry.register(cls)
