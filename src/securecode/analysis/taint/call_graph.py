"""Call graph construction for cross-function taint tracking."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from .models import CallGraph, CallSite, FunctionDefinition

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

logger = logging.getLogger(__name__)


class CallGraphBuilder:
    """Builds call graph from AST.

    Performs a two-pass analysis:
    - Pass 1: Function Discovery - Find all function declarations/expressions
    - Pass 2: Call Site Resolution - Find and resolve call sites
    - Pass 3: Build bidirectional call relationships
    """

    def __init__(self, language: str) -> None:
        """Initialize the builder.

        Args:
            language: Programming language ("typescript", "javascript", "csharp")
        """
        self.language = language
        self.source_code = ""

    def build(self, tree: "Tree", source: str) -> CallGraph:
        """Build call graph from parsed AST.

        Args:
            tree: Parsed AST from tree-sitter
            source: Source code text

        Returns:
            CallGraph with functions, call sites, and relationships
        """
        self.source_code = source

        call_graph = CallGraph(
            file_path="",  # Set by caller
            language=self.language,
            functions={},
            call_sites=[],
            calls_by_function={},
            callers_by_function={},
            unresolved_calls=[],
        )

        # Pass 1: Discover all function definitions
        self._discover_functions(tree.root_node, call_graph)
        logger.debug(f"Discovered {len(call_graph.functions)} functions")

        # Pass 2: Find and resolve call sites
        self._discover_calls(tree.root_node, call_graph)
        logger.debug(f"Discovered {len(call_graph.call_sites)} call sites")

        # Pass 3: Build bidirectional call relationships
        self._build_call_relationships(call_graph)

        return call_graph

    def _discover_functions(
        self,
        node: "Node",
        graph: CallGraph,
        current_class: Optional[str] = None,
    ) -> None:
        """Recursively discover function definitions.

        Args:
            node: Current AST node
            graph: CallGraph to populate
            current_class: Name of containing class (for methods)
        """
        if self.language in ("typescript", "javascript"):
            self._discover_ts_functions(node, graph, current_class)
        elif self.language == "csharp":
            self._discover_csharp_functions(node, graph, current_class)

    def _discover_ts_functions(
        self,
        node: "Node",
        graph: CallGraph,
        current_class: Optional[str] = None,
    ) -> None:
        """Discover TypeScript/JavaScript functions.

        Args:
            node: Current AST node
            graph: CallGraph to populate
            current_class: Name of containing class
        """
        # Function declaration: function foo() {}
        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node:
                func_name = self._get_text(name_node)
                func_def = self._extract_ts_function(node, func_name, current_class)
                graph.functions[func_def.qualified_name] = func_def

        # Arrow function: const foo = () => {}
        elif node.type in ("lexical_declaration", "variable_declaration"):
            for declarator in self._find_children_by_type(node, "variable_declarator"):
                name_node = declarator.child_by_field_name("name")
                value_node = declarator.child_by_field_name("value")

                if name_node and value_node:
                    if value_node.type == "arrow_function":
                        func_name = self._get_text(name_node)
                        func_def = self._extract_ts_function(
                            value_node, func_name, current_class, is_arrow=True
                        )
                        graph.functions[func_def.qualified_name] = func_def
                    # Also handle function expressions: const foo = function() {}
                    elif value_node.type == "function_expression":
                        func_name = self._get_text(name_node)
                        func_def = self._extract_ts_function(
                            value_node, func_name, current_class
                        )
                        graph.functions[func_def.qualified_name] = func_def

        # Method definition in class
        elif node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                method_name = self._get_text(name_node)
                func_def = self._extract_ts_function(
                    node, method_name, current_class, is_method=True
                )
                graph.functions[func_def.qualified_name] = func_def

        # Class declaration - track class name for methods
        elif node.type == "class_declaration":
            class_name_node = node.child_by_field_name("name")
            if class_name_node:
                class_name = self._get_text(class_name_node)
                # Recurse into class body with class context
                for child in node.children:
                    self._discover_ts_functions(child, graph, class_name)
                return  # Don't recurse again below

        # Export statements: export function foo() {}
        elif node.type == "export_statement":
            # Check for exported function
            for child in node.children:
                if child.type in ("function_declaration", "lexical_declaration"):
                    self._discover_ts_functions(child, graph, current_class)

        # Recurse to children
        for child in node.children:
            self._discover_ts_functions(child, graph, current_class)

    def _extract_ts_function(
        self,
        node: "Node",
        name: str,
        class_name: Optional[str] = None,
        is_arrow: bool = False,
        is_method: bool = False,
    ) -> FunctionDefinition:
        """Extract function details from AST node.

        Args:
            node: Function AST node
            name: Function name
            class_name: Containing class name (for methods)
            is_arrow: Whether this is an arrow function
            is_method: Whether this is a method

        Returns:
            FunctionDefinition with extracted details
        """
        # Get parameters
        params: list[str] = []
        param_positions: dict[str, int] = {}

        params_node = node.child_by_field_name("parameters")
        if params_node:
            idx = 0
            for child in params_node.children:
                # Handle different parameter types
                if child.type in (
                    "required_parameter",
                    "optional_parameter",
                    "rest_parameter",
                ):
                    pattern = child.child_by_field_name("pattern")
                    if pattern:
                        param_name = self._get_text(pattern)
                        params.append(param_name)
                        param_positions[param_name] = idx
                        idx += 1
                # Simple identifier parameters (JavaScript style)
                elif child.type == "identifier":
                    param_name = self._get_text(child)
                    params.append(param_name)
                    param_positions[param_name] = idx
                    idx += 1
                # Destructuring patterns
                elif child.type in ("object_pattern", "array_pattern"):
                    # For destructuring, we track as a single param
                    param_name = f"__destructured_{idx}"
                    params.append(param_name)
                    param_positions[param_name] = idx
                    idx += 1

        # Get function body
        body_node = node.child_by_field_name("body")

        # Build qualified name
        qualified_name = f"{class_name}.{name}" if class_name else name

        # Check if async
        is_async = any(child.type == "async" for child in node.children)

        return FunctionDefinition(
            name=name,
            qualified_name=qualified_name,
            node=node,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            parameters=params,
            param_positions=param_positions,
            body_node=body_node,
            is_async=is_async,
            is_arrow_function=is_arrow,
            is_method=is_method,
            class_name=class_name,
        )

    def _discover_csharp_functions(
        self,
        node: "Node",
        graph: CallGraph,
        current_class: Optional[str] = None,
    ) -> None:
        """Discover C# methods.

        Args:
            node: Current AST node
            graph: CallGraph to populate
            current_class: Name of containing class
        """
        # Method declaration
        if node.type == "method_declaration":
            name_node = node.child_by_field_name("name")
            if name_node:
                method_name = self._get_text(name_node)
                func_def = self._extract_csharp_method(node, method_name, current_class)
                graph.functions[func_def.qualified_name] = func_def

        # Class declaration - track class name for methods
        elif node.type == "class_declaration":
            class_name_node = node.child_by_field_name("name")
            if class_name_node:
                class_name = self._get_text(class_name_node)
                for child in node.children:
                    self._discover_csharp_functions(child, graph, class_name)
                return

        # Recurse to children
        for child in node.children:
            self._discover_csharp_functions(child, graph, current_class)

    def _extract_csharp_method(
        self,
        node: "Node",
        name: str,
        class_name: Optional[str] = None,
    ) -> FunctionDefinition:
        """Extract C# method details.

        Args:
            node: Method AST node
            name: Method name
            class_name: Containing class name

        Returns:
            FunctionDefinition with extracted details
        """
        params: list[str] = []
        param_positions: dict[str, int] = {}

        params_node = node.child_by_field_name("parameters")
        if params_node:
            idx = 0
            for child in params_node.children:
                if child.type == "parameter":
                    name_node = child.child_by_field_name("name")
                    if name_node:
                        param_name = self._get_text(name_node)
                        params.append(param_name)
                        param_positions[param_name] = idx
                        idx += 1

        body_node = node.child_by_field_name("body")
        qualified_name = f"{class_name}.{name}" if class_name else name

        # Check for async modifier
        is_async = any(
            child.type == "modifier" and self._get_text(child) == "async"
            for child in node.children
        )

        return FunctionDefinition(
            name=name,
            qualified_name=qualified_name,
            node=node,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            parameters=params,
            param_positions=param_positions,
            body_node=body_node,
            is_async=is_async,
            is_arrow_function=False,
            is_method=True,
            class_name=class_name,
        )

    def _discover_calls(
        self,
        node: "Node",
        graph: CallGraph,
        current_function: Optional[str] = None,
    ) -> None:
        """Discover call sites in the AST.

        Args:
            node: Current AST node
            graph: CallGraph to populate
            current_function: Name of containing function
        """
        # Track which function we're inside
        if node.type in (
            "function_declaration",
            "arrow_function",
            "method_definition",
            "function_expression",
        ):
            # Find function name from graph
            for func_def in graph.functions.values():
                if func_def.node == node:
                    current_function = func_def.qualified_name
                    break

        # Found a call expression
        if node.type == "call_expression":
            call_site = self._extract_call_site(node, current_function, graph)
            graph.call_sites.append(call_site)

        # C#: invocation expression
        elif node.type == "invocation_expression":
            call_site = self._extract_csharp_call_site(node, current_function, graph)
            graph.call_sites.append(call_site)

        # Recurse
        for child in node.children:
            self._discover_calls(child, graph, current_function)

    def _extract_call_site(
        self,
        node: "Node",
        caller: Optional[str],
        graph: CallGraph,
    ) -> CallSite:
        """Extract call site details for TypeScript/JavaScript.

        Args:
            node: Call expression AST node
            caller: Name of calling function
            graph: CallGraph for resolution

        Returns:
            CallSite with extracted details
        """
        function_node = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")

        # Resolve function name
        func_name = ""
        qualified_name = ""
        is_external = True
        resolved_def: Optional[FunctionDefinition] = None

        if function_node:
            func_text = self._get_text(function_node)

            # Simple identifier: foo()
            if function_node.type == "identifier":
                func_name = func_text
                qualified_name = func_text
                # Check if defined in this file
                if func_text in graph.functions:
                    is_external = False
                    resolved_def = graph.functions[func_text]

            # Member expression: obj.method()
            elif function_node.type == "member_expression":
                property_node = function_node.child_by_field_name("property")
                if property_node:
                    func_name = self._get_text(property_node)
                    qualified_name = func_text

                    # Check if it's a method call on 'this'
                    object_node = function_node.child_by_field_name("object")
                    if object_node and self._get_text(object_node) == "this":
                        # Try to find in current class
                        for func_def in graph.functions.values():
                            if func_def.is_method and func_def.name == func_name:
                                qualified_name = func_def.qualified_name
                                is_external = False
                                resolved_def = func_def
                                break

        # Extract arguments
        arguments: list["Node"] = []
        if args_node:
            for child in args_node.children:
                if child.type not in (",", "(", ")"):
                    arguments.append(child)

        return CallSite(
            function_name=func_name,
            qualified_name=qualified_name,
            node=node,
            line=node.start_point[0] + 1,
            column=node.start_point[1] + 1,
            arguments=arguments,
            argument_count=len(arguments),
            is_external=is_external,
            resolved_definition=resolved_def,
        )

    def _extract_csharp_call_site(
        self,
        node: "Node",
        caller: Optional[str],
        graph: CallGraph,
    ) -> CallSite:
        """Extract call site details for C#.

        Args:
            node: Invocation expression AST node
            caller: Name of calling function
            graph: CallGraph for resolution

        Returns:
            CallSite with extracted details
        """
        func_name = ""
        qualified_name = ""
        is_external = True
        resolved_def: Optional[FunctionDefinition] = None

        # Get the function being called
        function_node = node.child_by_field_name("function")
        if function_node:
            func_text = self._get_text(function_node)

            if function_node.type == "identifier":
                func_name = func_text
                qualified_name = func_text
            elif function_node.type == "member_access_expression":
                name_node = function_node.child_by_field_name("name")
                if name_node:
                    func_name = self._get_text(name_node)
                    qualified_name = func_text

        # Try to resolve
        for func_def in graph.functions.values():
            if func_def.name == func_name:
                qualified_name = func_def.qualified_name
                is_external = False
                resolved_def = func_def
                break

        # Extract arguments
        arguments: list["Node"] = []
        args_node = node.child_by_field_name("arguments")
        if args_node:
            for child in args_node.children:
                if child.type == "argument":
                    arguments.append(child)
                elif child.type not in (",", "(", ")"):
                    arguments.append(child)

        return CallSite(
            function_name=func_name,
            qualified_name=qualified_name,
            node=node,
            line=node.start_point[0] + 1,
            column=node.start_point[1] + 1,
            arguments=arguments,
            argument_count=len(arguments),
            is_external=is_external,
            resolved_definition=resolved_def,
        )

    def _build_call_relationships(self, graph: CallGraph) -> None:
        """Build bidirectional call relationships.

        Populates:
        - calls_by_function: caller -> list of CallSites
        - callers_by_function: callee -> list of CallSites calling it
        - unresolved_calls: calls we couldn't resolve

        Args:
            graph: CallGraph to update
        """
        for call_site in graph.call_sites:
            # Track calls from caller
            caller_func = self._find_containing_function(call_site.node, graph)
            if caller_func:
                if caller_func.qualified_name not in graph.calls_by_function:
                    graph.calls_by_function[caller_func.qualified_name] = []
                graph.calls_by_function[caller_func.qualified_name].append(call_site)

            # Track calls to callee
            if call_site.resolved_definition:
                callee_name = call_site.resolved_definition.qualified_name
                if callee_name not in graph.callers_by_function:
                    graph.callers_by_function[callee_name] = []
                graph.callers_by_function[callee_name].append(call_site)
            else:
                graph.unresolved_calls.append(call_site)

    def _find_containing_function(
        self,
        node: "Node",
        graph: CallGraph,
    ) -> Optional[FunctionDefinition]:
        """Find which function contains this node.

        Args:
            node: AST node to find container for
            graph: CallGraph with function definitions

        Returns:
            FunctionDefinition containing the node, or None
        """
        current = node.parent
        while current:
            for func_def in graph.functions.values():
                if func_def.node == current:
                    return func_def
            current = current.parent
        return None

    def _get_text(self, node: "Node") -> str:
        """Get text content of node.

        Args:
            node: AST node

        Returns:
            Source text for the node
        """
        return self.source_code[node.start_byte : node.end_byte]

    def _find_children_by_type(
        self,
        node: "Node",
        types: str | set[str],
    ) -> list["Node"]:
        """Find direct children of given type(s).

        Args:
            node: Parent node
            types: Type name or set of type names

        Returns:
            List of matching child nodes
        """
        if isinstance(types, str):
            types = {types}
        return [child for child in node.children if child.type in types]
