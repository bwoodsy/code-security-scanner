"""XSS (Cross-Site Scripting) detection rules for TypeScript/JavaScript."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Tree


@register_rule
class XSSRule(Rule):
    """Detects potential XSS vulnerabilities in TypeScript/JavaScript code."""

    rule_id = "TS-XSS-001"
    language = "typescript"
    vulnerability_type = VulnerabilityType.XSS
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe_id = "CWE-79"
    owasp_category = "A03:2021"

    title = "Potential Cross-Site Scripting (XSS) Vulnerability"
    description = (
        "The code uses a DOM manipulation method that can execute arbitrary HTML/JavaScript. "
        "If user-controlled data is passed to this method without proper sanitization, "
        "it could lead to XSS attacks."
    )
    remediation = (
        "1. Use textContent instead of innerHTML when displaying text\n"
        "2. Use a trusted sanitization library like DOMPurify\n"
        "3. In React, avoid dangerouslySetInnerHTML\n"
        "4. In Angular, use DomSanitizer.bypassSecurityTrustHtml only when necessary"
    )

    # Dangerous DOM properties and methods
    DANGEROUS_PATTERNS = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "document.writeln",
    ]

    # React-specific patterns
    REACT_PATTERNS = [
        "dangerouslySetInnerHTML",
    ]

    # jQuery patterns
    JQUERY_PATTERNS = [
        r"\.html\s*\(",
        r"\.append\s*\(",
        r"\.prepend\s*\(",
        r"\.after\s*\(",
        r"\.before\s*\(",
    ]

    # Known sanitization functions/methods that indicate safe usage
    SANITIZER_PATTERNS = [
        "DOMPurify.sanitize",
        "sanitizeHtml",
        "sanitize",
        "xss",  # xss library
        "escapeHtml",
        "escape",
        "htmlEscape",
        "encodeHTML",
        "encodeHTMLEntities",
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect XSS vulnerabilities."""
        matches: list[RuleMatch] = []

        # Find assignment expressions and member expressions
        self._find_dangerous_assignments(tree.root_node, source, matches)

        # Find dangerous function calls
        self._find_dangerous_calls(tree.root_node, source, matches)

        # Find React dangerouslySetInnerHTML
        self._find_react_dangerous(tree.root_node, source, matches)

        # Find eval usage
        self._find_eval_usage(tree.root_node, source, matches)

        return matches

    def _is_sanitized_value(
        self,
        value_node: "Node",
        source: str,
        function_scope: "Node",
    ) -> bool:
        """
        Check if a value is sanitized by a known sanitization function.

        This method checks:
        1. If the value is a direct call to a sanitizer (e.g., DOMPurify.sanitize(x))
        2. If the value is a variable that was assigned from a sanitizer call

        Args:
            value_node: The AST node representing the value being assigned
            source: The source code
            function_scope: The function containing this assignment

        Returns:
            True if the value is sanitized, False otherwise
        """
        from tree_sitter import Node

        # Get the text of the value being assigned
        value_text = self._get_node_text(value_node, source).strip()

        # Case 1: Direct call to sanitizer (e.g., innerHTML = DOMPurify.sanitize(x))
        if value_node.type == "call_expression":
            function = value_node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)
                for sanitizer in self.SANITIZER_PATTERNS:
                    if sanitizer in func_text:
                        return True

        # Case 2: Variable that was assigned from a sanitizer
        # Look for variable declarations/assignments in the function scope
        if value_node.type == "identifier":
            var_name = value_text
            return self._is_variable_sanitized(var_name, function_scope, source)

        return False

    def _is_variable_sanitized(
        self,
        var_name: str,
        function_scope: "Node",
        source: str,
    ) -> bool:
        """
        Check if a variable was assigned from a sanitizer call.

        Searches the function scope for variable declarations/assignments
        to find if the variable comes from a sanitization function.

        Args:
            var_name: Name of the variable to check
            function_scope: The function AST node to search within
            source: The source code

        Returns:
            True if variable was assigned from a sanitizer, False otherwise
        """
        from tree_sitter import Node

        # Search for variable declarations (const/let/var)
        def search_for_sanitized_assignment(node: "Node") -> bool:
            # Check variable_declarator: const clean = DOMPurify.sanitize(...)
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = self._get_node_text(name_node, source).strip()
                    if name == var_name:
                        # Check if value is a sanitizer call
                        value = node.child_by_field_name("value")
                        if value and value.type == "call_expression":
                            function = value.child_by_field_name("function")
                            if function:
                                func_text = self._get_node_text(function, source)
                                for sanitizer in self.SANITIZER_PATTERNS:
                                    if sanitizer in func_text:
                                        return True

            # Check assignment_expression: clean = DOMPurify.sanitize(...)
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                if left:
                    left_text = self._get_node_text(left, source).strip()
                    if left_text == var_name:
                        right = node.child_by_field_name("right")
                        if right and right.type == "call_expression":
                            function = right.child_by_field_name("function")
                            if function:
                                func_text = self._get_node_text(function, source)
                                for sanitizer in self.SANITIZER_PATTERNS:
                                    if sanitizer in func_text:
                                        return True

            # Recursively search children
            for child in node.children:
                if search_for_sanitized_assignment(child):
                    return True

            return False

        return search_for_sanitized_assignment(function_scope)

    def _get_function_scope(self, node: "Node") -> "Node | None":
        """
        Find the containing function scope for a given node.

        Traverses up the AST to find the nearest function declaration,
        arrow function, or method definition.

        Args:
            node: The AST node to start from

        Returns:
            The function scope node, or None if not in a function
        """
        from tree_sitter import Node

        current = node
        while current:
            if current.type in [
                "function_declaration",
                "function",
                "arrow_function",
                "method_definition",
                "function_expression",
            ]:
                return current
            current = current.parent
        return None

    def _find_dangerous_assignments(
        self,
        node: "Node",
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find assignments to dangerous DOM properties."""
        from tree_sitter import Node

        # Look for assignment expressions
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left and left.type == "member_expression":
                property_node = left.child_by_field_name("property")
                if property_node:
                    prop_text = self._get_node_text(property_node, source)
                    if prop_text in ["innerHTML", "outerHTML"]:
                        # Get the value being assigned
                        right = node.child_by_field_name("right")

                        # Check if the value is sanitized
                        is_sanitized = False
                        if right:
                            function_scope = self._get_function_scope(node)
                            if function_scope:
                                is_sanitized = self._is_sanitized_value(
                                    right, source, function_scope
                                )

                        # Only report if not sanitized
                        if not is_sanitized:
                            matches.append(
                                RuleMatch(
                                    line=node.start_point[0] + 1,
                                    column=node.start_point[1] + 1,
                                    end_line=node.end_point[0] + 1,
                                    end_column=node.end_point[1] + 1,
                                    matched_code=self._get_node_text(node, source),
                                    context={"property": prop_text},
                                )
                            )

        # Recurse into children
        for child in node.children:
            self._find_dangerous_assignments(child, source, matches)

    def _find_dangerous_calls(
        self,
        node: "Node",
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find calls to dangerous DOM methods."""
        from tree_sitter import Node

        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)

                # Check for document.write
                if "document.write" in func_text or "document.writeln" in func_text:
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=self._get_node_text(node, source),
                            context={"method": "document.write"},
                        )
                    )

                # Check for insertAdjacentHTML
                if "insertAdjacentHTML" in func_text:
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=self._get_node_text(node, source),
                            context={"method": "insertAdjacentHTML"},
                        )
                    )

                # Check for jQuery html()
                if func_text.endswith(".html") or ".html(" in func_text:
                    # Make sure it has arguments (setting, not getting)
                    args = node.child_by_field_name("arguments")
                    if args and len(args.children) > 2:  # Has at least one argument
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(node, source),
                                context={"method": "jQuery.html"},
                            )
                        )

        for child in node.children:
            self._find_dangerous_calls(child, source, matches)

    def _find_react_dangerous(
        self,
        node: "Node",
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find React dangerouslySetInnerHTML usage."""
        from tree_sitter import Node

        # Look for JSX attributes named dangerouslySetInnerHTML
        if node.type in ["jsx_attribute", "property_identifier"]:
            text = self._get_node_text(node, source)
            if "dangerouslySetInnerHTML" in text:
                matches.append(
                    RuleMatch(
                        line=node.start_point[0] + 1,
                        column=node.start_point[1] + 1,
                        end_line=node.end_point[0] + 1,
                        end_column=node.end_point[1] + 1,
                        matched_code=self._get_node_text(node.parent if node.parent else node, source),
                        context={"framework": "react", "property": "dangerouslySetInnerHTML"},
                    )
                )

        for child in node.children:
            self._find_react_dangerous(child, source, matches)

    def _find_eval_usage(
        self,
        node: "Node",
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find eval() and similar dangerous function calls."""
        from tree_sitter import Node

        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)
                if func_text in ["eval", "Function", "setTimeout", "setInterval"]:
                    # For setTimeout/setInterval, only flag if first arg is a string
                    if func_text in ["setTimeout", "setInterval"]:
                        args = node.child_by_field_name("arguments")
                        if args:
                            first_arg = None
                            for child in args.children:
                                if child.type not in ["(", ")", ","]:
                                    first_arg = child
                                    break
                            if first_arg and first_arg.type == "string":
                                matches.append(
                                    RuleMatch(
                                        line=node.start_point[0] + 1,
                                        column=node.start_point[1] + 1,
                                        end_line=node.end_point[0] + 1,
                                        end_column=node.end_point[1] + 1,
                                        matched_code=self._get_node_text(node, source),
                                        context={"function": func_text, "issue": "string argument"},
                                    )
                                )
                    else:
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(node, source),
                                context={"function": func_text},
                            )
                        )

        for child in node.children:
            self._find_eval_usage(child, source, matches)
