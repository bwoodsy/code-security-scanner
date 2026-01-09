"""Data models for cross-function taint tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from tree_sitter import Node


@dataclass
class FunctionDefinition:
    """Represents a function definition in the AST.

    Captures all relevant information about a function including its
    parameters, body, location, and analysis state.
    """

    # Identity
    name: str  # Simple name: "getUserData"
    qualified_name: str  # Qualified: "UserService.getUserData"

    # Location in source
    node: "Node"
    start_line: int
    end_line: int

    # Parameters
    parameters: list[str]  # Parameter names in order: ["id", "options"]
    param_positions: dict[str, int]  # name -> index: {"id": 0, "options": 1}

    # Function body
    body_node: Optional["Node"] = None

    # Analysis results (populated during analysis)
    returns_tainted: bool = False
    tainted_params: set[int] = field(default_factory=set)

    # Metadata
    is_async: bool = False
    is_arrow_function: bool = False
    is_method: bool = False
    class_name: Optional[str] = None

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"FunctionDefinition({self.qualified_name}, "
            f"params={self.parameters}, "
            f"lines={self.start_line}-{self.end_line})"
        )


@dataclass
class CallSite:
    """Represents a function call in the code.

    Captures where a function is called, what arguments are passed,
    and links to the function definition if resolvable.
    """

    # Call information
    function_name: str  # Simple name: "getUserData"
    qualified_name: str  # Resolved name: "UserService.getUserData"

    # Location
    node: "Node"
    line: int
    column: int

    # Arguments
    arguments: list["Node"]  # AST nodes for each argument
    argument_count: int

    # Taint state at call site (populated during analysis)
    tainted_args: set[int] = field(default_factory=set)  # Indices of tainted args

    # Resolution
    resolved_definition: Optional[FunctionDefinition] = None
    is_external: bool = False  # True if call to imported/external function

    def __repr__(self) -> str:
        """String representation for debugging."""
        resolved = "resolved" if self.resolved_definition else "unresolved"
        return f"CallSite({self.qualified_name} at line {self.line}, {resolved})"


@dataclass
class CallGraph:
    """Per-file call graph representation.

    Maintains the complete function call structure for a single file,
    including all function definitions and call relationships.
    """

    # File information
    file_path: str
    language: str

    # Function registry
    functions: dict[str, FunctionDefinition]  # qualified_name -> definition

    # Call relationships
    call_sites: list[CallSite]  # All call sites in the file
    calls_by_function: dict[str, list[CallSite]]  # caller -> callees
    callers_by_function: dict[str, list[CallSite]]  # callee -> call sites

    # Analysis metadata
    unresolved_calls: list[CallSite] = field(default_factory=list)

    def get_function(self, name: str) -> Optional[FunctionDefinition]:
        """Get function definition by name.

        Args:
            name: Function name (qualified or simple)

        Returns:
            FunctionDefinition if found, None otherwise
        """
        return self.functions.get(name)

    def get_callers(self, function_name: str) -> list[CallSite]:
        """Get all call sites that invoke a function.

        Args:
            function_name: Qualified function name

        Returns:
            List of CallSite objects that call this function
        """
        return self.callers_by_function.get(function_name, [])

    def get_callees(self, function_name: str) -> list[CallSite]:
        """Get all functions called by a function.

        Args:
            function_name: Qualified function name

        Returns:
            List of CallSite objects for functions this function calls
        """
        return self.calls_by_function.get(function_name, [])

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"CallGraph({self.language}, "
            f"{len(self.functions)} functions, "
            f"{len(self.call_sites)} calls)"
        )


@dataclass
class TaintState:
    """Tracks taint status of a variable or expression.

    Records whether data is tainted, where it came from,
    how it propagated, and if it was sanitized.
    """

    is_tainted: bool
    source_type: Optional[str] = None  # "req.body", "parameter:userId", etc.
    source_line: Optional[int] = None

    # Propagation path
    propagation_path: list[str] = field(default_factory=list)

    # Sanitization
    is_sanitized: bool = False
    sanitizer_type: Optional[str] = None
    sanitizer_line: Optional[int] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "is_tainted": self.is_tainted,
            "source_type": self.source_type,
            "source_line": self.source_line,
            "propagation_path": self.propagation_path,
            "is_sanitized": self.is_sanitized,
            "sanitizer_type": self.sanitizer_type,
            "sanitizer_line": self.sanitizer_line,
        }


@dataclass
class FunctionSummary:
    """Summarizes taint behavior of a function.

    Records how taint propagates through a function:
    - Which parameters contribute to return value taint
    - Whether the function returns tainted data
    - Whether the function performs sanitization
    """

    function_def: FunctionDefinition

    # Parameter taint sensitivity
    # Maps param_index -> whether that param taints the return value
    param_taints_return: dict[int, bool] = field(default_factory=dict)

    # Return value taint
    returns_tainted_value: bool = False
    tainted_if_params: set[int] = field(default_factory=set)  # Tainted if these params are

    # Sanitization performed
    performs_sanitization: bool = False
    sanitization_patterns: list[str] = field(default_factory=list)

    # Analysis status
    analyzed: bool = False
    analysis_depth: int = 0

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"FunctionSummary({self.function_def.name}, "
            f"returns_tainted={self.returns_tainted_value}, "
            f"sanitizes={self.performs_sanitization})"
        )


@dataclass
class CrossFunctionTrace:
    """Result of cross-function taint analysis.

    Contains complete trace information from a sink back to a source,
    potentially crossing multiple function boundaries.
    """

    # Source information
    source_found: bool = False
    source_type: Optional[str] = None
    source_line: Optional[int] = None

    # Trace path across functions
    trace_path: list[str] = field(default_factory=list)
    function_chain: list[str] = field(default_factory=list)  # Function call chain

    # Depth tracking
    max_depth_reached: int = 0
    depth_limit_hit: bool = False

    # Analysis quality
    confidence: float = 1.0  # Decreases with depth and uncertainty
    needs_manual_review: bool = False

    # Sanitization
    sanitization_found: bool = False
    sanitizer_location: Optional[tuple[str, int]] = None  # (function_name, line)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "source_found": self.source_found,
            "source_type": self.source_type,
            "source_line": self.source_line,
            "trace_path": self.trace_path,
            "function_chain": self.function_chain,
            "max_depth_reached": self.max_depth_reached,
            "depth_limit_hit": self.depth_limit_hit,
            "confidence": self.confidence,
            "needs_manual_review": self.needs_manual_review,
            "sanitization_found": self.sanitization_found,
            "sanitizer_location": self.sanitizer_location,
        }

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"CrossFunctionTrace(source_found={self.source_found}, "
            f"depth={self.max_depth_reached}, "
            f"confidence={self.confidence:.2f})"
        )
