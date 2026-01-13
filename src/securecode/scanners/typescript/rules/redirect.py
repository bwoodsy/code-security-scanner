"""Open redirect detection rules for TypeScript/JavaScript."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class OpenRedirectRule(Rule):
    """Detects potential open redirect vulnerabilities."""

    rule_id = "TS-REDIR-001"
    language = "typescript"
    vulnerability_type = VulnerabilityType.OPEN_REDIRECT
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    cwe_id = "CWE-601"
    owasp_category = "A01:2021"

    title = "Potential Open Redirect Vulnerability"
    description = (
        "The code redirects to a URL that may be user-controlled. "
        "An attacker could redirect users to a malicious site for phishing attacks."
    )
    remediation = (
        "1. Use a whitelist of allowed redirect destinations\n"
        "2. Only allow relative URLs for redirects\n"
        "3. Validate the URL starts with your domain\n"
        "4. Use URL parsing to verify the hostname"
    )

    # Patterns that indicate proper redirect validation (reduce false positives)
    REDIRECT_VALIDATION_PATTERNS = [
        # Relative URL check (starts with /)
        r"\.startsWith\s*\(\s*['\"]\/['\"]",
        r"\.startsWith\s*\(\s*['\"]\.\/['\"]",
        r"\.startsWith\s*\(\s*['\"]\.\.\/['\"]",
        # Same-origin/hostname validation
        r"\.hostname\s*===",
        r"\.host\s*===",
        r"\.origin\s*===",
        r"new\s+URL\s*\([^)]+\)\s*\.\s*(hostname|host|origin)\s*===",
        # Built-in validation functions
        r"Url\.IsLocalUrl\s*\(",
        r"isLocalUrl\s*\(",
        r"isSafeUrl\s*\(",
        r"isRelativeUrl\s*\(",
        r"validateUrl\s*\(",
        r"isValidRedirect\s*\(",
        r"isTrustedUrl\s*\(",
        # Whitelist/allowlist check
        r"(allowedUrls|allowedDomains|trustedDomains|whitelist|allowlist|validUrls)\s*\.\s*(includes|has|indexOf|some)",
        # Protocol check
        r"\.protocol\s*===\s*['\"]https?:?['\"]",
        r"\.startsWith\s*\(\s*['\"]https?:\/\/['\"]",
        # URL constructor for parsing (common validation pattern)
        r"new\s+URL\s*\([^)]+\)",
        # Regex validation for allowed patterns
        r"\.match\s*\(\s*\/\^",
        r"\.test\s*\(\s*\/\^",
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect open redirect vulnerabilities."""
        matches: list[RuleMatch] = []
        self._find_unsafe_redirects(tree.root_node, source, matches)
        return matches

    def _find_unsafe_redirects(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find redirects with user-controlled URLs."""
        # Check for Express/Koa redirect
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)

                # Express res.redirect()
                if ".redirect" in func_text:
                    args = node.child_by_field_name("arguments")
                    if args and self._has_user_controlled_url(args, source):
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(node, source),
                                context={
                                    "function": "redirect",
                                    "type": "express_redirect",
                                },
                            )
                        )

        # Check for window.location assignments
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right:
                left_text = self._get_node_text(left, source)

                location_properties = [
                    "window.location.href",
                    "window.location",
                    "location.href",
                    "document.location",
                    "document.location.href",
                ]

                if any(prop in left_text for prop in location_properties):
                    right_text = self._get_node_text(right, source)
                    if self._looks_like_user_input(right_text):
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(node, source),
                                context={
                                    "property": left_text,
                                    "type": "location_assignment",
                                },
                            )
                        )

        # Check for window.open() with user input
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)
                if func_text in ["window.open", "open"]:
                    args = node.child_by_field_name("arguments")
                    if args:
                        args_text = self._get_node_text(args, source)
                        if self._looks_like_user_input(args_text):
                            matches.append(
                                RuleMatch(
                                    line=node.start_point[0] + 1,
                                    column=node.start_point[1] + 1,
                                    end_line=node.end_point[0] + 1,
                                    end_column=node.end_point[1] + 1,
                                    matched_code=self._get_node_text(node, source),
                                    context={
                                        "function": "window.open",
                                        "type": "window_open",
                                    },
                                )
                            )

        for child in node.children:
            self._find_unsafe_redirects(child, source, matches)

    def _has_user_controlled_url(self, args_node: Node, source: str) -> bool:
        """Check if redirect arguments contain user-controlled URLs."""
        args_text = self._get_node_text(args_node, source)

        if not self._looks_like_user_input(args_text):
            return False

        # Check if there's proper validation in scope
        if self._has_redirect_validation(args_node, source):
            return False  # Validated redirect is likely safe

        return True

    def _looks_like_user_input(self, text: str) -> bool:
        """Check if text looks like it contains user input."""
        user_input_patterns = [
            "req.query", "req.params", "req.body",
            "request.query", "request.params", "request.body",
            "ctx.query", "ctx.params",
            "searchParams", "URLSearchParams",
            "query.", "params.",
            "returnUrl", "redirectUrl", "redirect_uri", "next",
            "callback", "return_to", "goto", "target",
        ]
        return any(pattern in text for pattern in user_input_patterns)

    def _get_function_scope(self, node: Node) -> Node | None:
        """
        Find the containing function scope for a given node.

        Traverses up the AST to find the nearest function declaration,
        arrow function, or method definition.
        """
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

    def _has_redirect_validation(self, node: Node, source: str) -> bool:
        """
        Check if the redirect has proper URL validation in scope.

        Searches the containing function for patterns that indicate
        the redirect URL is being validated (e.g., hostname checks,
        whitelist validation, relative URL checks).
        """
        # Get the containing function scope
        function_scope = self._get_function_scope(node)
        if not function_scope:
            # No function scope - check a reasonable context window
            start = max(0, node.start_byte - 500)
            end = min(len(source), node.end_byte + 500)
            scope_text = source[start:end]
        else:
            scope_text = self._get_node_text(function_scope, source)

        # Check for any validation patterns
        for pattern in self.REDIRECT_VALIDATION_PATTERNS:
            if re.search(pattern, scope_text, re.IGNORECASE):
                return True

        return False
