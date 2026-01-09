"""Taint tracking module for data flow analysis.

This module provides comprehensive taint analysis capabilities:
- Single-file taint tracking (TaintTracker)
- Cross-function taint analysis (CrossFunctionTaintTracker)
- Call graph construction (CallGraphBuilder)
- Function summary analysis (FunctionSummaryAnalyzer)

Example - Basic Taint Tracking:
    from securecode.analysis.taint import TaintTracker
    from securecode.parsers.typescript import TypeScriptParser

    parser = TypeScriptParser()
    tree = parser.parse(source_code)

    tracker = TaintTracker(language="typescript")
    analysis = tracker.analyze(tree, source_code)

    if analysis.is_tainted("userId", line=42):
        print("Variable 'userId' is tainted at line 42")

Example - Cross-Function Analysis:
    from securecode.analysis.taint import CallGraphBuilder, CrossFunctionTaintTracker

    builder = CallGraphBuilder("typescript")
    call_graph = builder.build(tree, source_code)

    tracker = CrossFunctionTaintTracker(call_graph, max_depth=3)
    trace = tracker.trace_parameter_source("myFunc", param_index=0, start_line=42)
"""

from .call_graph import CallGraphBuilder
from .function_summary import FunctionSummaryAnalyzer
from .models import (
    CallGraph,
    CallSite,
    CrossFunctionTrace,
    FunctionDefinition,
    FunctionSummary,
    TaintState,
)
from .taint_tracker import TaintTracker as CrossFunctionTaintTracker
from .tracker import TaintAnalysis, TaintFlow, TaintStep, TaintTracker

__all__ = [
    # Main taint tracking
    "TaintTracker",
    "TaintAnalysis",
    "TaintFlow",
    "TaintStep",
    # Cross-function tracking
    "CrossFunctionTaintTracker",
    "CallGraphBuilder",
    "CallGraph",
    "FunctionSummaryAnalyzer",
    # Models
    "FunctionDefinition",
    "CallSite",
    "FunctionSummary",
    "TaintState",
    "CrossFunctionTrace",
]
