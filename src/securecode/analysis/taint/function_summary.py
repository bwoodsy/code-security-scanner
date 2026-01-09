"""Function summary analyzer for taint tracking.

Analyzes functions to create summaries of their taint behavior, enabling
efficient interprocedural analysis without re-analyzing function bodies
multiple times.

Example:
    >>> from securecode.analysis.taint import FunctionSummaryAnalyzer
    >>>
    >>> analyzer = FunctionSummaryAnalyzer(call_graph, source_code)
    >>> summary = analyzer.analyze_function("processUserInput")
    >>>
    >>> if summary.returns_tainted_value:
    >>>     print(f"Function returns tainted data if params {summary.tainted_if_params} are tainted")
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Optional

from securecode.analysis.sources_sinks import get_sanitizers, get_sources

from .models import FunctionSummary

if TYPE_CHECKING:
    from tree_sitter import Node

    from .models import CallGraph, FunctionDefinition

logger = logging.getLogger(__name__)


class FunctionSummaryAnalyzer:
    """Analyzes functions to create taint behavior summaries.

    Creates reusable summaries that capture:
    - Which parameters taint the return value
    - Whether function performs sanitization
    - Whether function always returns tainted/untainted data
    - What transformations the function performs

    These summaries enable efficient interprocedural analysis by avoiding
    repeated analysis of the same functions.

    Attributes:
        call_graph: CallGraph containing function definitions
        source_code: Source code for text extraction
        summaries: Cache of analyzed function summaries
    """

    def __init__(self, call_graph: CallGraph, source_code: str = "") -> None:
        """Initialize the function summary analyzer.

        Args:
            call_graph: CallGraph with function definitions
            source_code: Source code text
        """
        self.call_graph = call_graph
        self.source_code = source_code
        self.summaries: dict[str, FunctionSummary] = {}

        # Compile patterns
        self.sanitizer_patterns = self._compile_sanitizer_patterns()
        self.source_patterns = self._compile_source_patterns()

    def analyze_function(self, function_name: str) -> Optional[FunctionSummary]:
        """Analyze a function and create a taint behavior summary.

        Args:
            function_name: Qualified function name to analyze

        Returns:
            FunctionSummary if function found, None otherwise
        """
        # Check cache first
        if function_name in self.summaries:
            return self.summaries[function_name]

        # Get function definition
        func_def = self.call_graph.get_function(function_name)
        if not func_def:
            logger.debug(f"Function {function_name} not found in call graph")
            return None

        # Create summary
        summary = FunctionSummary(
            function_def=func_def,
            analyzed=False,
        )

        # Analyze function body
        if func_def.body_node:
            self._analyze_function_body(func_def, summary)
        else:
            # External or abstract function - conservative analysis
            summary.returns_tainted_value = True
            summary.tainted_if_params = set(range(len(func_def.parameters)))
            logger.debug(f"No body for {function_name}, assuming conservative taint")

        summary.analyzed = True
        self.summaries[function_name] = summary

        logger.debug(
            f"Analyzed {function_name}: "
            f"returns_tainted={summary.returns_tainted_value}, "
            f"sanitizes={summary.performs_sanitization}"
        )

        return summary

    def analyze_all_functions(self) -> dict[str, FunctionSummary]:
        """Analyze all functions in the call graph.

        Returns:
            Dictionary mapping function names to summaries
        """
        for func_name in self.call_graph.functions.keys():
            self.analyze_function(func_name)

        return self.summaries

    def _analyze_function_body(
        self,
        func_def: FunctionDefinition,
        summary: FunctionSummary,
    ) -> None:
        """Analyze function body to determine taint behavior.

        Args:
            func_def: Function definition to analyze
            summary: FunctionSummary to populate
        """
        if not func_def.body_node:
            return

        # Track which parameters are used in return statements
        param_usage_in_returns: set[str] = set()
        performs_sanitization = False

        # Analyze return statements
        return_nodes = self._find_return_statements(func_def.body_node)
        for return_node in return_nodes:
            # Get return value expression
            value_node = return_node.child_by_field_name("value")
            if value_node:
                # Check which parameters are used
                used_params = self._find_used_parameters(value_node, func_def)
                param_usage_in_returns.update(used_params)

                # Check if return value is sanitized
                if self._contains_sanitization(value_node):
                    performs_sanitization = True

        # Check for sanitization anywhere in function body
        if self._contains_sanitization(func_def.body_node):
            performs_sanitization = True
            # Extract sanitization patterns
            sanitizers = self._extract_sanitization_patterns(func_def.body_node)
            summary.sanitization_patterns = sanitizers

        # Determine if return value is tainted
        if param_usage_in_returns:
            # Return value depends on parameters
            summary.returns_tainted_value = True
            summary.tainted_if_params = {
                func_def.param_positions[p]
                for p in param_usage_in_returns
                if p in func_def.param_positions
            }

            # Build param_taints_return mapping
            for param_name in param_usage_in_returns:
                if param_name in func_def.param_positions:
                    param_idx = func_def.param_positions[param_name]
                    summary.param_taints_return[param_idx] = True
        else:
            # Return value doesn't depend on parameters
            # Check if it returns a taint source
            if self._returns_taint_source(func_def.body_node):
                summary.returns_tainted_value = True
            else:
                summary.returns_tainted_value = False

        summary.performs_sanitization = performs_sanitization

    def _find_return_statements(self, node: Node) -> list[Node]:
        """Find all return statements in a node.

        Args:
            node: AST node to search

        Returns:
            List of return statement nodes
        """
        results: list[Node] = []

        if node.type == "return_statement":
            results.append(node)

        for child in node.children:
            results.extend(self._find_return_statements(child))

        return results

    def _find_used_parameters(
        self,
        node: Node,
        func_def: FunctionDefinition,
    ) -> set[str]:
        """Find which function parameters are used in an expression.

        Args:
            node: Expression AST node
            func_def: Function definition with parameter info

        Returns:
            Set of parameter names used in the expression
        """
        used_params: set[str] = set()

        if node.type == "identifier":
            var_name = self._get_text(node)
            if var_name in func_def.parameters:
                used_params.add(var_name)

        for child in node.children:
            used_params.update(self._find_used_parameters(child, func_def))

        return used_params

    def _contains_sanitization(self, node: Node) -> bool:
        """Check if node contains sanitization operations.

        Args:
            node: AST node to check

        Returns:
            True if sanitization is detected
        """
        node_text = self._get_text(node)

        for pattern in self.sanitizer_patterns:
            if pattern.search(node_text):
                return True

        return False

    def _extract_sanitization_patterns(self, node: Node) -> list[str]:
        """Extract sanitization patterns from a node.

        Args:
            node: AST node to analyze

        Returns:
            List of sanitization pattern descriptions
        """
        patterns: list[str] = []
        node_text = self._get_text(node)

        for pattern in self.sanitizer_patterns:
            match = pattern.search(node_text)
            if match:
                # Extract matched text
                matched = match.group(0) if match else pattern.pattern
                patterns.append(matched)

        return list(set(patterns))  # Deduplicate

    def _returns_taint_source(self, node: Node) -> bool:
        """Check if function returns a taint source directly.

        Args:
            node: Function body node

        Returns:
            True if returns a known taint source
        """
        return_nodes = self._find_return_statements(node)

        for return_node in return_nodes:
            value_node = return_node.child_by_field_name("value")
            if value_node:
                value_text = self._get_text(value_node)
                if self._is_taint_source(value_text):
                    return True

        return False

    def _is_taint_source(self, text: str) -> bool:
        """Check if text contains a taint source.

        Args:
            text: Code text to check

        Returns:
            True if contains a taint source
        """
        for pattern in self.source_patterns:
            if pattern.search(text):
                return True
        return False

    def _compile_sanitizer_patterns(self) -> list[re.Pattern]:
        """Compile sanitizer patterns for efficient matching.

        Returns:
            List of compiled regex patterns
        """
        sanitizers = get_sanitizers(self.call_graph.language)
        patterns = []
        for sanitizer in sanitizers:
            try:
                patterns.append(re.compile(sanitizer, re.IGNORECASE))
            except re.error:
                logger.warning(f"Invalid sanitizer pattern: {sanitizer}")
        return patterns

    def _compile_source_patterns(self) -> list[re.Pattern]:
        """Compile source patterns for efficient matching.

        Returns:
            List of compiled regex patterns
        """
        sources = get_sources(self.call_graph.language)
        patterns = []
        for source in sources:
            escaped = re.escape(source)
            try:
                patterns.append(re.compile(escaped, re.IGNORECASE))
            except re.error:
                logger.warning(f"Invalid source pattern: {source}")
        return patterns

    def _get_text(self, node: Node) -> str:
        """Get text content of a node.

        Args:
            node: AST node

        Returns:
            Source text for the node
        """
        if not self.source_code:
            return ""
        return self.source_code[node.start_byte:node.end_byte]


class SummaryCache:
    """Cache for function summaries to improve performance.

    Maintains a persistent cache of function summaries across multiple
    files and analysis runs. Uses function signature and body hash to
    detect when summaries need to be recomputed.

    Attributes:
        cache: Dictionary mapping function signatures to summaries
        hits: Number of cache hits
        misses: Number of cache misses
    """

    def __init__(self) -> None:
        """Initialize the summary cache."""
        self.cache: dict[str, FunctionSummary] = {}
        self.hits = 0
        self.misses = 0

    def get(self, function_signature: str) -> Optional[FunctionSummary]:
        """Get a summary from cache.

        Args:
            function_signature: Unique function signature

        Returns:
            Cached summary if available, None otherwise
        """
        summary = self.cache.get(function_signature)
        if summary:
            self.hits += 1
        else:
            self.misses += 1
        return summary

    def put(self, function_signature: str, summary: FunctionSummary) -> None:
        """Store a summary in cache.

        Args:
            function_signature: Unique function signature
            summary: Summary to cache
        """
        self.cache[function_signature] = summary

    def clear(self) -> None:
        """Clear the cache."""
        self.cache.clear()
        self.hits = 0
        self.misses = 0

    def stats(self) -> dict[str, int]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0.0

        return {
            "hits": self.hits,
            "misses": self.misses,
            "total_requests": total,
            "hit_rate_percent": round(hit_rate, 2),
            "cached_entries": len(self.cache),
        }
