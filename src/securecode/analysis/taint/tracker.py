"""Production-grade taint tracking engine for semantic code analysis.

This module provides a comprehensive taint analysis system that tracks how data
flows from untrusted sources (user input) to dangerous sinks (SQL queries, file
operations, etc.) through AST-based semantic analysis.

The engine performs:
- Source identification: Detects user input origins (req.params, Request.Query, etc.)
- Taint propagation: Tracks data flow through assignments, calls, and transformations
- Sanitization detection: Recognizes when data is cleaned or validated
- Sink analysis: Evaluates whether tainted data reaches dangerous operations

Example:
    >>> from securecode.analysis.taint import TaintTracker
    >>> from securecode.parsers.typescript import TypeScriptParser
    >>>
    >>> parser = TypeScriptParser()
    >>> tree = parser.parse(source_code)
    >>> tracker = TaintTracker(language="typescript")
    >>> analysis = tracker.analyze(tree, source_code)
    >>>
    >>> # Check if a variable is tainted
    >>> if analysis.is_tainted("userId", line=42):
    >>>     print("Variable 'userId' contains tainted data at line 42")
    >>>
    >>> # Get taint flow paths
    >>> for flow in analysis.taint_flows:
    >>>     print(f"Tainted data flows from {flow.source} to {flow.sink}")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from securecode.analysis.sources_sinks import (
    get_sanitizers,
    get_sources,
    is_safe_value,
)

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

logger = logging.getLogger(__name__)


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class TaintStep:
    """Represents a single step in taint propagation.

    Captures one transformation or assignment in the data flow chain from
    source to sink. Each step records the line, variable involved, and the
    type of operation that occurred.

    Attributes:
        line: Line number where this step occurs
        variable: Variable name involved in this step
        operation: Type of operation ("assignment", "concatenation", "call", "property_access", etc.)
        details: Additional context about the operation
    """

    line: int
    variable: str
    operation: str
    details: str = ""

    def __repr__(self) -> str:
        """String representation for debugging."""
        if self.details:
            return f"TaintStep(line={self.line}, var={self.variable}, op={self.operation}, {self.details})"
        return f"TaintStep(line={self.line}, var={self.variable}, op={self.operation})"


@dataclass
class TaintFlow:
    """Complete taint flow from source to sink.

    Represents a complete path where tainted data flows from a user input
    source through various transformations to a dangerous sink without
    proper sanitization.

    Attributes:
        source_type: Type of taint source ("req.params", "Request.Query", etc.)
        source_line: Line where taint originates
        sink_variable: Variable used at the dangerous sink
        sink_line: Line where sink operation occurs
        sink_type: Type of sink ("sql_query", "file_operation", etc.)
        steps: List of TaintStep objects showing propagation path
        is_sanitized: Whether sanitization was detected in the flow
        sanitizer_info: Information about sanitization if detected
        confidence: Confidence level (0.0-1.0) in this flow
    """

    source_type: str
    source_line: int
    sink_variable: str
    sink_line: int
    sink_type: str
    steps: list[TaintStep] = field(default_factory=list)
    is_sanitized: bool = False
    sanitizer_info: Optional[str] = None
    confidence: float = 1.0

    def __repr__(self) -> str:
        """String representation for debugging."""
        sanitized_str = " (SANITIZED)" if self.is_sanitized else ""
        return (
            f"TaintFlow({self.source_type}:{self.source_line} -> "
            f"{self.sink_variable}:{self.sink_line} [{self.sink_type}]{sanitized_str})"
        )


@dataclass
class TaintAnalysis:
    """Results of taint analysis for a file.

    Contains all taint tracking results including which variables are tainted,
    complete taint flows, and analysis metadata.

    Attributes:
        tainted_vars: Map of variable name to list of line numbers where tainted
        taint_flows: List of complete TaintFlow objects from sources to sinks
        sanitized_vars: Variables that were tainted but then sanitized
        sources: Map of line number to source type
        sinks: Map of line number to sink type
        analysis_complete: Whether analysis finished successfully
        error_message: Error message if analysis failed
    """

    tainted_vars: dict[str, list[int]] = field(default_factory=dict)
    taint_flows: list[TaintFlow] = field(default_factory=list)
    sanitized_vars: dict[str, int] = field(default_factory=dict)  # var -> sanitization line
    sources: dict[int, str] = field(default_factory=dict)  # line -> source_type
    sinks: dict[int, str] = field(default_factory=dict)  # line -> sink_type
    analysis_complete: bool = False
    error_message: Optional[str] = None

    def is_tainted(self, variable: str, line: int) -> bool:
        """Check if a variable is tainted at a specific line.

        Args:
            variable: Variable name to check
            line: Line number to check at

        Returns:
            True if variable is tainted at that line, False otherwise
        """
        if variable not in self.tainted_vars:
            return False

        # Check if variable was tainted before this line
        taint_lines = self.tainted_vars[variable]
        for taint_line in taint_lines:
            if taint_line <= line:
                # Check if it was sanitized between taint and this line
                if variable in self.sanitized_vars:
                    sanitize_line = self.sanitized_vars[variable]
                    if taint_line < sanitize_line <= line:
                        return False  # Was sanitized
                return True
        return False

    def get_taint_path(self, sink_var: str, sink_line: int) -> Optional[list[TaintStep]]:
        """Get the taint propagation path to a specific sink.

        Args:
            sink_var: Variable at the sink
            sink_line: Line number of the sink

        Returns:
            List of TaintStep objects showing the path, or None if not found
        """
        for flow in self.taint_flows:
            if flow.sink_variable == sink_var and flow.sink_line == sink_line:
                return flow.steps
        return None


# =============================================================================
# Main Taint Tracker
# =============================================================================


class TaintTracker:
    """Production-grade taint tracking engine.

    Performs semantic analysis of code to track data flow from untrusted sources
    to dangerous sinks. Uses AST-based analysis to understand:
    - Where tainted data originates (sources)
    - How it propagates through the code (assignments, calls, operations)
    - Where it's used dangerously (sinks)
    - Whether it's properly sanitized

    Attributes:
        language: Programming language being analyzed
        max_trace_depth: Maximum depth for backward tracing
        source_patterns: Compiled regex patterns for identifying sources
        sanitizer_patterns: Compiled regex patterns for identifying sanitizers
    """

    def __init__(self, language: str, max_trace_depth: int = 50) -> None:
        """Initialize the taint tracker.

        Args:
            language: Language to analyze ("typescript", "javascript", "csharp")
            max_trace_depth: Maximum depth for backward data flow tracing
        """
        self.language = language
        self.max_trace_depth = max_trace_depth
        self.source_code = ""
        self.source_lines: list[str] = []

        # Compile patterns for performance
        self.source_patterns = self._compile_source_patterns()
        self.sanitizer_patterns = self._compile_sanitizer_patterns()

        # Analysis state
        self.taint_state: dict[str, set[int]] = {}  # var -> set of lines where tainted
        self.sanitizations: dict[str, int] = {}  # var -> line where sanitized
        self.assignments: dict[str, list[tuple[int, str]]] = {}  # var -> [(line, rhs), ...]

    def analyze(self, tree: Tree, source: str) -> TaintAnalysis:
        """Analyze a file for tainted data flows.

        Performs complete taint analysis including:
        1. Source identification
        2. Taint propagation tracking
        3. Sanitization detection
        4. Sink evaluation
        5. Flow path construction

        Args:
            tree: Parsed AST from tree-sitter
            source: Source code text

        Returns:
            TaintAnalysis with complete analysis results
        """
        self.source_code = source
        self.source_lines = source.split("\n")

        # Reset analysis state
        self.taint_state = {}
        self.sanitizations = {}
        self.assignments = {}

        analysis = TaintAnalysis()

        try:
            # Pass 1: Identify all sources (where taint originates)
            self._identify_sources(tree.root_node, analysis)
            logger.debug(f"Identified {len(analysis.sources)} taint sources")

            # Pass 2: Track taint propagation through assignments and operations
            self._track_propagation(tree.root_node, analysis)
            logger.debug(f"Tracked taint to {len(self.taint_state)} variables")

            # Pass 3: Detect sanitization points
            self._detect_sanitization(tree.root_node, analysis)
            logger.debug(f"Found {len(analysis.sanitized_vars)} sanitizations")

            # Pass 4: Identify sinks and build flows
            self._identify_sinks_and_flows(tree.root_node, analysis)
            logger.debug(f"Identified {len(analysis.taint_flows)} taint flows")

            # Finalize tainted_vars dict
            for var, line_set in self.taint_state.items():
                analysis.tainted_vars[var] = sorted(list(line_set))

            analysis.analysis_complete = True

        except Exception as e:
            logger.error(f"Taint analysis failed: {e}", exc_info=True)
            analysis.analysis_complete = False
            analysis.error_message = str(e)

        return analysis

    def _identify_sources(self, node: Node, analysis: TaintAnalysis) -> None:
        """Identify taint sources in the AST.

        Finds all user input sources and marks their variables as tainted.

        Args:
            node: Current AST node
            analysis: TaintAnalysis to populate
        """
        if self.language in ("typescript", "javascript"):
            self._identify_ts_sources(node, analysis)
        elif self.language == "csharp":
            self._identify_csharp_sources(node, analysis)

        # Recurse to children
        for child in node.children:
            self._identify_sources(child, analysis)

    def _identify_ts_sources(self, node: Node, analysis: TaintAnalysis) -> None:
        """Identify TypeScript/JavaScript taint sources.

        Detects:
        - req.params, req.query, req.body, etc.
        - Function parameters (marked as potentially tainted)
        - Document/window location properties
        - Storage APIs

        Args:
            node: Current AST node
            analysis: TaintAnalysis to populate
        """
        # Member expressions: req.params, req.query, etc.
        if node.type == "member_expression":
            text = self._get_text(node)
            source_type = self._match_source(text)
            if source_type:
                line = node.start_point[0] + 1
                analysis.sources[line] = source_type

                # Try to extract variable being assigned
                var_name = self._find_assignment_target(node)
                if var_name:
                    self._mark_tainted(var_name, line)

        # Subscript: req.params['id'], request.query["search"]
        elif node.type == "subscript_expression":
            object_node = node.child_by_field_name("object")
            if object_node:
                text = self._get_text(object_node)
                source_type = self._match_source(text)
                if source_type:
                    line = node.start_point[0] + 1
                    analysis.sources[line] = source_type

                    var_name = self._find_assignment_target(node)
                    if var_name:
                        self._mark_tainted(var_name, line)

        # Function parameters - mark as potentially tainted
        elif node.type in ("required_parameter", "optional_parameter"):
            pattern = node.child_by_field_name("pattern")
            if pattern and pattern.type == "identifier":
                param_name = self._get_text(pattern)
                line = node.start_point[0] + 1
                self._mark_tainted(param_name, line)
                analysis.sources[line] = f"parameter:{param_name}"

    def _identify_csharp_sources(self, node: Node, analysis: TaintAnalysis) -> None:
        """Identify C# taint sources.

        Detects:
        - Request.Query, Request.Form, Request.Body
        - Controller action parameters with [FromQuery], [FromBody] attributes
        - RouteData.Values

        Args:
            node: Current AST node
            analysis: TaintAnalysis to populate
        """
        # Member access: Request.Query, Request.Form
        if node.type == "member_access_expression":
            text = self._get_text(node)
            source_type = self._match_source(text)
            if source_type:
                line = node.start_point[0] + 1
                analysis.sources[line] = source_type

                var_name = self._find_assignment_target(node)
                if var_name:
                    self._mark_tainted(var_name, line)

        # Element access: Request.Query["id"]
        elif node.type == "element_access_expression":
            expression_node = node.child_by_field_name("expression")
            if expression_node:
                text = self._get_text(expression_node)
                source_type = self._match_source(text)
                if source_type:
                    line = node.start_point[0] + 1
                    analysis.sources[line] = source_type

                    var_name = self._find_assignment_target(node)
                    if var_name:
                        self._mark_tainted(var_name, line)

        # Parameters with attributes [FromQuery], [FromBody]
        elif node.type == "parameter":
            # Check for attributes
            for child in node.children:
                if child.type == "attribute_list":
                    attr_text = self._get_text(child)
                    if "FromQuery" in attr_text or "FromBody" in attr_text or "FromForm" in attr_text:
                        name_node = node.child_by_field_name("name")
                        if name_node:
                            param_name = self._get_text(name_node)
                            line = node.start_point[0] + 1
                            self._mark_tainted(param_name, line)
                            analysis.sources[line] = f"parameter:{param_name}"

    def _track_propagation(self, node: Node, analysis: TaintAnalysis) -> None:
        """Track how taint propagates through the code.

        Handles:
        - Direct assignment: const x = taintedVar
        - String concatenation: const x = "prefix" + taintedVar
        - Template literals: const x = `${taintedVar}`
        - Object property assignment: obj.prop = taintedVar
        - Array operations: arr.push(taintedVar)
        - Function calls: const x = processInput(taintedVar)

        Args:
            node: Current AST node
            analysis: TaintAnalysis to populate
        """
        if self.language in ("typescript", "javascript"):
            self._track_ts_propagation(node, analysis)
        elif self.language == "csharp":
            self._track_csharp_propagation(node, analysis)

        # Recurse
        for child in node.children:
            self._track_propagation(child, analysis)

    def _track_ts_propagation(self, node: Node, analysis: TaintAnalysis) -> None:
        """Track TypeScript/JavaScript taint propagation.

        Args:
            node: Current AST node
            analysis: TaintAnalysis to populate
        """
        # Variable declaration: const x = ...
        if node.type in ("lexical_declaration", "variable_declaration"):
            for declarator in self._find_children_by_type(node, {"variable_declarator"}):
                name_node = declarator.child_by_field_name("name")
                value_node = declarator.child_by_field_name("value")

                if name_node and value_node:
                    var_name = self._get_text(name_node)
                    line = declarator.start_point[0] + 1

                    # Check if RHS is tainted
                    if self._is_expression_tainted(value_node, line):
                        self._mark_tainted(var_name, line)
                        self.assignments.setdefault(var_name, []).append(
                            (line, self._get_text(value_node))
                        )

        # Assignment expression: x = ...
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")

            if left and right:
                line = node.start_point[0] + 1

                # Simple identifier assignment
                if left.type == "identifier":
                    var_name = self._get_text(left)
                    if self._is_expression_tainted(right, line):
                        self._mark_tainted(var_name, line)

                # Property assignment: obj.prop = tainted
                elif left.type == "member_expression":
                    if self._is_expression_tainted(right, line):
                        # Mark the object as tainted
                        object_node = left.child_by_field_name("object")
                        if object_node and object_node.type == "identifier":
                            obj_name = self._get_text(object_node)
                            self._mark_tainted(obj_name, line)

        # Template literals with substitutions
        elif node.type == "template_string":
            line = node.start_point[0] + 1
            for child in node.children:
                if child.type == "template_substitution":
                    # Check if substitution contains tainted data
                    if self._contains_tainted_identifier(child, line):
                        # Mark the template result as tainted
                        # Try to find what it's assigned to
                        var_name = self._find_assignment_target(node)
                        if var_name:
                            self._mark_tainted(var_name, line)

        # Binary expression (concatenation): "string" + var
        elif node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            if operator and self._get_text(operator) == "+":
                line = node.start_point[0] + 1
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")

                # If either side is tainted, result is tainted
                if (left and self._is_expression_tainted(left, line)) or \
                   (right and self._is_expression_tainted(right, line)):
                    var_name = self._find_assignment_target(node)
                    if var_name:
                        self._mark_tainted(var_name, line)

        # Call expression - check if arguments are tainted
        elif node.type == "call_expression":
            line = node.start_point[0] + 1
            args = node.child_by_field_name("arguments")

            if args and self._contains_tainted_identifier(args, line):
                # Return value might be tainted
                var_name = self._find_assignment_target(node)
                if var_name:
                    # Conservative: assume function returns tainted data if input is tainted
                    self._mark_tainted(var_name, line)

        # Array expressions: [tainted, ...]
        elif node.type == "array":
            line = node.start_point[0] + 1
            if self._contains_tainted_identifier(node, line):
                var_name = self._find_assignment_target(node)
                if var_name:
                    self._mark_tainted(var_name, line)

        # Object expressions: { prop: tainted }
        elif node.type == "object":
            line = node.start_point[0] + 1
            if self._contains_tainted_identifier(node, line):
                var_name = self._find_assignment_target(node)
                if var_name:
                    self._mark_tainted(var_name, line)

    def _track_csharp_propagation(self, node: Node, analysis: TaintAnalysis) -> None:
        """Track C# taint propagation.

        Args:
            node: Current AST node
            analysis: TaintAnalysis to populate
        """
        # Variable declaration: var x = ...
        if node.type == "variable_declaration":
            declarator = node.child_by_field_name("declarator")
            if declarator:
                for child in declarator.children:
                    if child.type == "variable_declarator":
                        name_node = child.child_by_field_name("name")
                        value_node = child.child_by_field_name("value")

                        if name_node and value_node:
                            var_name = self._get_text(name_node)
                            line = child.start_point[0] + 1

                            if self._is_expression_tainted(value_node, line):
                                self._mark_tainted(var_name, line)

        # Assignment expression: x = ...
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")

            if left and right:
                line = node.start_point[0] + 1

                if left.type == "identifier":
                    var_name = self._get_text(left)
                    if self._is_expression_tainted(right, line):
                        self._mark_tainted(var_name, line)

                # Property assignment
                elif left.type == "member_access_expression":
                    if self._is_expression_tainted(right, line):
                        expression = left.child_by_field_name("expression")
                        if expression and expression.type == "identifier":
                            obj_name = self._get_text(expression)
                            self._mark_tainted(obj_name, line)

        # String interpolation: $"{tainted}"
        elif node.type == "interpolated_string_expression":
            line = node.start_point[0] + 1
            if self._contains_tainted_identifier(node, line):
                var_name = self._find_assignment_target(node)
                if var_name:
                    self._mark_tainted(var_name, line)

        # Binary expression (concatenation): "string" + var
        elif node.type == "binary_expression":
            line = node.start_point[0] + 1
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")

            if (left and self._is_expression_tainted(left, line)) or \
               (right and self._is_expression_tainted(right, line)):
                var_name = self._find_assignment_target(node)
                if var_name:
                    self._mark_tainted(var_name, line)

    def _detect_sanitization(self, node: Node, analysis: TaintAnalysis) -> None:
        """Detect where variables are sanitized.

        Identifies sanitization operations:
        - parseInt(), Number() - numeric conversion
        - encodeURIComponent() - URL encoding
        - DOMPurify.sanitize() - HTML sanitization
        - Parameterized queries
        - Validation functions

        Args:
            node: Current AST node
            analysis: TaintAnalysis to populate
        """
        # Call expressions - check for sanitizer functions
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_text(function)
                line = node.start_point[0] + 1

                # Check if this is a sanitizer
                if self._is_sanitizer_call(func_text):
                    # Find what variable this sanitizes
                    var_name = self._find_assignment_target(node)
                    if var_name:
                        analysis.sanitized_vars[var_name] = line
                        self.sanitizations[var_name] = line

                    # Also check if argument is a tainted variable
                    args = node.child_by_field_name("arguments")
                    if args:
                        for arg in args.children:
                            if arg.type == "identifier":
                                arg_name = self._get_text(arg)
                                if arg_name in self.taint_state:
                                    # This variable is being sanitized
                                    if var_name:
                                        analysis.sanitized_vars[var_name] = line
                                        self.sanitizations[var_name] = line

        # Recurse
        for child in node.children:
            self._detect_sanitization(child, analysis)

    def _identify_sinks_and_flows(self, node: Node, analysis: TaintAnalysis) -> None:
        """Identify dangerous sinks and construct taint flows.

        Finds operations where tainted data is used dangerously and builds
        complete TaintFlow objects showing the path from source to sink.

        Args:
            node: Current AST node
            analysis: TaintAnalysis to populate
        """
        # This is a simplified sink detection - in practice, you'd check
        # specific patterns like query(), exec(), etc.

        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_text(function)
                line = node.start_point[0] + 1

                # Check if this is a dangerous sink
                sink_type = self._identify_sink_type(func_text)
                if sink_type:
                    analysis.sinks[line] = sink_type

                    # Check if arguments contain tainted data
                    args = node.child_by_field_name("arguments")
                    if args:
                        for arg in args.children:
                            if arg.type not in (",", "(", ")"):
                                tainted_vars = self._extract_tainted_variables(arg, line)

                                for var_name in tainted_vars:
                                    # Build a taint flow
                                    flow = self._build_taint_flow(
                                        var_name, line, sink_type, analysis
                                    )
                                    if flow:
                                        analysis.taint_flows.append(flow)

        # Recurse
        for child in node.children:
            self._identify_sinks_and_flows(child, analysis)

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _compile_source_patterns(self) -> list[re.Pattern]:
        """Compile source patterns for efficient matching."""
        sources = get_sources(self.language)
        patterns = []
        for source in sources:
            # Escape special regex characters
            escaped = re.escape(source)
            patterns.append(re.compile(escaped, re.IGNORECASE))
        return patterns

    def _compile_sanitizer_patterns(self) -> list[re.Pattern]:
        """Compile sanitizer patterns for efficient matching."""
        sanitizers = get_sanitizers(self.language)
        patterns = []
        for sanitizer in sanitizers:
            # These are already regex patterns
            try:
                patterns.append(re.compile(sanitizer, re.IGNORECASE))
            except re.error:
                logger.warning(f"Invalid sanitizer pattern: {sanitizer}")
        return patterns

    def _match_source(self, text: str) -> Optional[str]:
        """Check if text matches a known source pattern."""
        for pattern in self.source_patterns:
            if pattern.search(text):
                return pattern.pattern.replace("\\", "")
        return None

    def _is_sanitizer_call(self, func_text: str) -> bool:
        """Check if function call is a sanitizer."""
        for pattern in self.sanitizer_patterns:
            if pattern.search(func_text):
                return True
        return False

    def _identify_sink_type(self, func_text: str) -> Optional[str]:
        """Identify if this is a dangerous sink and what type."""
        func_lower = func_text.lower()

        # SQL sinks
        if any(s in func_lower for s in ["query", "execute", "sql", "$queryraw", "$executeraw"]):
            return "sql_query"

        # Command sinks
        if any(s in func_lower for s in ["exec", "spawn", "process.start"]):
            return "command_execution"

        # File sinks
        if any(s in func_lower for s in ["readfile", "writefile", "file.read", "file.write"]):
            return "file_operation"

        # HTTP sinks
        if any(s in func_lower for s in ["fetch", "axios", "http.request", "httpclient"]):
            return "http_request"

        # XSS sinks
        if any(s in func_lower for s in ["innerhtml", "outerhtml", "document.write"]):
            return "dom_manipulation"

        return None

    def _mark_tainted(self, var_name: str, line: int) -> None:
        """Mark a variable as tainted at a specific line."""
        if var_name not in self.taint_state:
            self.taint_state[var_name] = set()
        self.taint_state[var_name].add(line)

    def _is_expression_tainted(self, node: Node, current_line: int) -> bool:
        """Check if an expression contains tainted data."""
        # Simple identifier
        if node.type == "identifier":
            var_name = self._get_text(node)
            return self._is_var_tainted(var_name, current_line)

        # Member expression
        if node.type == "member_expression":
            object_node = node.child_by_field_name("object")
            if object_node and object_node.type == "identifier":
                var_name = self._get_text(object_node)
                return self._is_var_tainted(var_name, current_line)

        # Check all children
        return self._contains_tainted_identifier(node, current_line)

    def _contains_tainted_identifier(self, node: Node, current_line: int) -> bool:
        """Recursively check if node contains any tainted identifier."""
        if node.type == "identifier":
            var_name = self._get_text(node)
            if self._is_var_tainted(var_name, current_line):
                return True

        for child in node.children:
            if self._contains_tainted_identifier(child, current_line):
                return True

        return False

    def _is_var_tainted(self, var_name: str, current_line: int) -> bool:
        """Check if a variable is tainted before a given line."""
        if var_name not in self.taint_state:
            return False

        # Check if tainted before this line
        taint_lines = self.taint_state[var_name]
        for taint_line in taint_lines:
            if taint_line <= current_line:
                # Check if sanitized
                if var_name in self.sanitizations:
                    sanitize_line = self.sanitizations[var_name]
                    if taint_line < sanitize_line <= current_line:
                        return False
                return True

        return False

    def _find_assignment_target(self, node: Node) -> Optional[str]:
        """Find what variable a node is being assigned to."""
        current = node.parent
        while current:
            # Variable declarator: const x = ...
            if current.type == "variable_declarator":
                name_node = current.child_by_field_name("name")
                if name_node and name_node.type == "identifier":
                    return self._get_text(name_node)

            # Assignment: x = ...
            elif current.type == "assignment_expression":
                left = current.child_by_field_name("left")
                if left and left.type == "identifier":
                    return self._get_text(left)

            current = current.parent

        return None

    def _extract_tainted_variables(self, node: Node, line: int) -> list[str]:
        """Extract all tainted variable names from a node."""
        tainted = []

        if node.type == "identifier":
            var_name = self._get_text(node)
            if self._is_var_tainted(var_name, line):
                tainted.append(var_name)

        for child in node.children:
            tainted.extend(self._extract_tainted_variables(child, line))

        return tainted

    def _build_taint_flow(
        self,
        sink_var: str,
        sink_line: int,
        sink_type: str,
        analysis: TaintAnalysis,
    ) -> Optional[TaintFlow]:
        """Build a complete TaintFlow from source to sink."""
        # Find where this variable was first tainted
        if sink_var not in self.taint_state:
            return None

        taint_lines = sorted(list(self.taint_state[sink_var]))
        if not taint_lines:
            return None

        source_line = taint_lines[0]
        source_type = analysis.sources.get(source_line, "unknown")

        # Check if sanitized
        is_sanitized = False
        sanitizer_info = None
        if sink_var in self.sanitizations:
            sanitize_line = self.sanitizations[sink_var]
            if source_line < sanitize_line < sink_line:
                is_sanitized = True
                sanitizer_info = f"Sanitized at line {sanitize_line}"

        # Build steps (simplified - in production, track actual propagation)
        steps = [
            TaintStep(
                line=source_line,
                variable=sink_var,
                operation="source",
                details=f"Tainted from {source_type}"
            )
        ]

        # Add intermediate assignments
        if sink_var in self.assignments:
            for assign_line, rhs in self.assignments[sink_var]:
                if source_line < assign_line < sink_line:
                    steps.append(
                        TaintStep(
                            line=assign_line,
                            variable=sink_var,
                            operation="assignment",
                            details=f"Assigned from: {rhs[:50]}"
                        )
                    )

        # Add sink step
        steps.append(
            TaintStep(
                line=sink_line,
                variable=sink_var,
                operation="sink",
                details=f"Used in {sink_type}"
            )
        )

        return TaintFlow(
            source_type=source_type,
            source_line=source_line,
            sink_variable=sink_var,
            sink_line=sink_line,
            sink_type=sink_type,
            steps=steps,
            is_sanitized=is_sanitized,
            sanitizer_info=sanitizer_info,
            confidence=0.8 if not is_sanitized else 0.3
        )

    def _get_text(self, node: Node) -> str:
        """Get text content of a node."""
        return self.source_code[node.start_byte:node.end_byte]

    def _find_children_by_type(self, node: Node, types: set[str]) -> list[Node]:
        """Find direct children matching given types."""
        return [child for child in node.children if child.type in types]
