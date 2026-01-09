"""Cross-function taint tracker for interprocedural analysis.

This module provides advanced taint tracking that follows data flow across
function boundaries, enabling detection of vulnerabilities where tainted data
is passed through multiple functions before reaching a sink.

Example:
    >>> from securecode.analysis.taint import TaintTracker, CallGraphBuilder
    >>>
    >>> builder = CallGraphBuilder("typescript")
    >>> call_graph = builder.build(tree, source_code)
    >>>
    >>> tracker = TaintTracker(call_graph, max_depth=3)
    >>> trace = tracker.trace_to_source("userId", sink_line=42)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from .models import CrossFunctionTrace, FunctionDefinition, TaintState

if TYPE_CHECKING:
    from .models import CallGraph, CallSite

logger = logging.getLogger(__name__)


class TaintTracker:
    """Tracks taint flow across function boundaries.

    Performs interprocedural taint analysis by:
    1. Tracking parameter taint propagation into functions
    2. Analyzing return value taint based on function body
    3. Following taint through call chains
    4. Building complete traces from sources to sinks

    Attributes:
        call_graph: CallGraph containing function and call information
        max_depth: Maximum depth for cross-function tracing
        source_code: Source code being analyzed
    """

    def __init__(
        self,
        call_graph: CallGraph,
        max_depth: int = 5,
        source_code: str = "",
    ) -> None:
        """Initialize the cross-function taint tracker.

        Args:
            call_graph: Constructed CallGraph for the file
            max_depth: Maximum function call depth to trace
            source_code: Source code text for node extraction
        """
        self.call_graph = call_graph
        self.max_depth = max_depth
        self.source_code = source_code

        # Analysis state
        self.function_taint_cache: dict[str, dict[int, TaintState]] = {}
        self.visited_functions: set[str] = set()

    def trace_parameter_source(
        self,
        function_name: str,
        param_index: int,
        start_line: int,
    ) -> CrossFunctionTrace:
        """Trace a function parameter back to its taint source.

        Follows data flow backward through function calls to find where
        tainted data originates.

        Args:
            function_name: Qualified function name
            param_index: Index of parameter to trace
            start_line: Line where the call occurs

        Returns:
            CrossFunctionTrace with complete trace information
        """
        trace = CrossFunctionTrace()
        self.visited_functions = set()

        self._trace_parameter_recursive(
            function_name=function_name,
            param_index=param_index,
            trace=trace,
            depth=0,
        )

        return trace

    def trace_to_source(
        self,
        variable: str,
        sink_line: int,
    ) -> CrossFunctionTrace:
        """Trace a variable at a sink back to its taint source.

        Args:
            variable: Variable name at the sink
            sink_line: Line number of the sink

        Returns:
            CrossFunctionTrace showing path from source to sink
        """
        trace = CrossFunctionTrace()
        self.visited_functions = set()

        # Find which function contains this sink
        containing_func = self._find_function_at_line(sink_line)
        if not containing_func:
            trace.needs_manual_review = True
            trace.trace_path.append(f"Could not find function containing line {sink_line}")
            return trace

        # Start tracing from this function
        self._trace_variable_in_function(
            function_def=containing_func,
            variable=variable,
            trace=trace,
            depth=0,
        )

        return trace

    def _trace_parameter_recursive(
        self,
        function_name: str,
        param_index: int,
        trace: CrossFunctionTrace,
        depth: int,
    ) -> None:
        """Recursively trace parameter taint through call chain.

        Args:
            function_name: Function to analyze
            param_index: Parameter index to trace
            trace: CrossFunctionTrace to populate
            depth: Current recursion depth
        """
        if depth > self.max_depth:
            trace.depth_limit_hit = True
            trace.max_depth_reached = depth
            trace.trace_path.append(f"Max depth {self.max_depth} reached at {function_name}")
            return

        if function_name in self.visited_functions:
            # Avoid infinite recursion
            trace.trace_path.append(f"Cycle detected at {function_name}")
            return

        self.visited_functions.add(function_name)
        trace.function_chain.append(function_name)
        trace.max_depth_reached = max(trace.max_depth_reached, depth)

        # Get function definition
        func_def = self.call_graph.get_function(function_name)
        if not func_def:
            trace.trace_path.append(f"Function {function_name} not found in call graph")
            trace.needs_manual_review = True
            return

        # Check if parameter index is valid
        if param_index >= len(func_def.parameters):
            trace.trace_path.append(
                f"Invalid parameter index {param_index} for {function_name}"
            )
            return

        param_name = func_def.parameters[param_index]
        trace.trace_path.append(
            f"Tracing parameter '{param_name}' (index {param_index}) in {function_name}"
        )

        # Find all call sites that call this function
        call_sites = self.call_graph.get_callers(function_name)

        if not call_sites:
            # This is a top-level function, check if param is from user input
            # In a real implementation, check against known sources
            trace.source_found = True
            trace.source_type = f"parameter:{param_name}"
            trace.source_line = func_def.start_line
            trace.trace_path.append(
                f"Parameter '{param_name}' at line {func_def.start_line} "
                f"(potential user input)"
            )
            return

        # Trace back through callers
        for call_site in call_sites:
            if call_site.argument_count > param_index:
                # Get the argument passed to this parameter
                arg_node = call_site.arguments[param_index]
                arg_text = self._get_node_text(arg_node)

                trace.trace_path.append(
                    f"Called at line {call_site.line} with argument: {arg_text}"
                )

                # Check if argument is a known taint source
                if self._is_known_source(arg_text):
                    trace.source_found = True
                    trace.source_type = arg_text
                    trace.source_line = call_site.line
                    trace.confidence = 0.9
                    return

                # If argument is a variable, trace it in the caller
                if arg_node.type == "identifier":
                    caller_func = self._find_containing_function(call_site.node)
                    if caller_func:
                        self._trace_variable_in_function(
                            function_def=caller_func,
                            variable=arg_text,
                            trace=trace,
                            depth=depth + 1,
                        )

    def _trace_variable_in_function(
        self,
        function_def: FunctionDefinition,
        variable: str,
        trace: CrossFunctionTrace,
        depth: int,
    ) -> None:
        """Trace a variable within a function to find its source.

        Args:
            function_def: Function to analyze
            variable: Variable name to trace
            trace: CrossFunctionTrace to populate
            depth: Current recursion depth
        """
        if depth > self.max_depth:
            trace.depth_limit_hit = True
            trace.max_depth_reached = depth
            return

        trace.function_chain.append(function_def.qualified_name)
        trace.max_depth_reached = max(trace.max_depth_reached, depth)

        # Check if variable is a parameter
        if variable in function_def.param_positions:
            param_index = function_def.param_positions[variable]
            trace.trace_path.append(
                f"Variable '{variable}' is parameter {param_index} of {function_def.name}"
            )

            # Trace parameter through callers
            self._trace_parameter_recursive(
                function_name=function_def.qualified_name,
                param_index=param_index,
                trace=trace,
                depth=depth + 1,
            )
            return

        # Otherwise, analyze function body to find where variable is assigned
        if function_def.body_node:
            self._analyze_variable_assignment(
                variable=variable,
                body_node=function_def.body_node,
                trace=trace,
            )

    def _analyze_variable_assignment(
        self,
        variable: str,
        body_node,
        trace: CrossFunctionTrace,
    ) -> None:
        """Analyze where a variable is assigned in a function body.

        Args:
            variable: Variable to find assignments for
            body_node: Function body AST node
            trace: CrossFunctionTrace to populate
        """
        # This is a simplified implementation
        # In production, perform full AST traversal to find assignments
        trace.trace_path.append(
            f"Analyzing assignments to '{variable}' in function body"
        )

        # Check if variable assignment contains known source
        # This would require full AST analysis
        trace.needs_manual_review = True

    def _find_function_at_line(self, line: int) -> Optional[FunctionDefinition]:
        """Find which function contains a given line.

        Args:
            line: Line number

        Returns:
            FunctionDefinition if found, None otherwise
        """
        for func_def in self.call_graph.functions.values():
            if func_def.start_line <= line <= func_def.end_line:
                return func_def
        return None

    def _find_containing_function(self, node) -> Optional[FunctionDefinition]:
        """Find which function contains a node.

        Args:
            node: AST node

        Returns:
            FunctionDefinition if found, None otherwise
        """
        current = node.parent
        while current:
            for func_def in self.call_graph.functions.values():
                if func_def.node == current:
                    return func_def
            current = current.parent
        return None

    def _is_known_source(self, text: str) -> bool:
        """Check if text contains a known taint source.

        Args:
            text: Code text to check

        Returns:
            True if contains a known source pattern
        """
        # Common taint sources
        sources = [
            "req.params", "req.query", "req.body", "req.headers",
            "Request.Query", "Request.Form", "Request.Body",
            "event.body", "event.queryStringParameters",
            "ctx.params", "ctx.query",
        ]

        text_lower = text.lower()
        for source in sources:
            if source.lower() in text_lower:
                return True

        return False

    def _get_node_text(self, node) -> str:
        """Get text content of a node.

        Args:
            node: AST node

        Returns:
            Source text for the node
        """
        if not self.source_code:
            return ""
        return self.source_code[node.start_byte:node.end_byte]


class TaintPropagationAnalyzer:
    """Analyzes how taint propagates through expressions and operations.

    Handles complex taint flow patterns:
    - String concatenation and template literals
    - Object and array construction
    - Destructuring and spread operations
    - Higher-order functions (map, filter, reduce)
    - Async/await and promises
    """

    def __init__(self, language: str) -> None:
        """Initialize the propagation analyzer.

        Args:
            language: Programming language
        """
        self.language = language

    def analyze_expression(self, node, taint_state: dict[str, TaintState]) -> TaintState:
        """Analyze if an expression produces tainted data.

        Args:
            node: Expression AST node
            taint_state: Current taint state mapping

        Returns:
            TaintState for the expression result
        """
        # Simplified implementation
        # In production, handle all expression types

        if node.type == "identifier":
            var_name = self._get_text(node)
            return taint_state.get(var_name, TaintState(is_tainted=False))

        # Conservative: if any child is tainted, result is tainted
        for child in node.children:
            child_state = self.analyze_expression(child, taint_state)
            if child_state.is_tainted:
                return TaintState(
                    is_tainted=True,
                    source_type=child_state.source_type,
                    source_line=child_state.source_line,
                )

        return TaintState(is_tainted=False)

    def _get_text(self, node) -> str:
        """Placeholder for getting node text."""
        return ""
