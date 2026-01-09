"""Server-Side Request Forgery (SSRF) detection rules for TypeScript/JavaScript."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class SSRFRule(Rule):
    """Detects potential Server-Side Request Forgery vulnerabilities."""

    rule_id = "TS-SSRF-001"
    language = "typescript"
    vulnerability_type = VulnerabilityType.SSRF
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    cwe_id = "CWE-918"
    owasp_category = "A10:2021"

    title = "Potential Server-Side Request Forgery (SSRF)"
    description = (
        "The code makes HTTP requests to URLs that may be controlled by user input. "
        "An attacker could use this to access internal services, read sensitive data, "
        "or perform actions on behalf of the server."
    )
    remediation = (
        "1. Validate and sanitize all URL inputs\n"
        "2. Use an allowlist of permitted domains/hosts\n"
        "3. Block requests to internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x)\n"
        "4. Use a URL parser to validate the scheme and host\n"
        "5. Avoid passing user input directly to HTTP client functions"
    )

    # HTTP client functions that can be SSRF vectors
    HTTP_CLIENTS = [
        "fetch",
        "axios",
        "axios.get",
        "axios.post",
        "axios.put",
        "axios.delete",
        "axios.patch",
        "axios.request",
        "http.request",
        "http.get",
        "https.request",
        "https.get",
        "request",
        "got",
        "got.get",
        "got.post",
        "superagent",
        "needle",
        "node-fetch",
        "undici.fetch",
        "undici.request",
    ]

    # User input sources that indicate SSRF risk
    USER_INPUT_PATTERNS = [
        r"req\.(?:params|query|body|headers)",
        r"request\.(?:params|query|body|headers)",
        r"ctx\.(?:params|query|request)",
        r"event\.(?:body|queryStringParameters|pathParameters)",
        r"\.getItem\(",  # localStorage/sessionStorage
        r"location\.",
        r"document\.URL",
        r"window\.location",
    ]

    # Safe patterns that indicate URL is validated
    SAFE_PATTERNS = [
        r"\bnew\s+URL\s*\(",  # URL constructor with word boundary
        r"=\s*URL\s*\(",  # URL constructor assignment
        r"\.startsWith\s*\(\s*['\"]https?://",  # Protocol check
        r"\.hostname\s*===",  # Hostname validation
        r"\.host\s*===",
        r"\ballowlist\b",  # Use word boundaries to avoid partial matches
        r"\bwhitelist\b",
        r"\ballowedHosts\b",
        r"\ballowedDomains\b",
        r"\bvalidHosts\b",
        r"\bisValidUrl\s*\(",  # Function call with word boundary
        r"\bvalidateUrl\s*\(",  # Function call with word boundary
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect SSRF vulnerabilities."""
        matches: list[RuleMatch] = []
        self._find_ssrf_patterns(tree.root_node, source, matches)
        return matches

    def _find_ssrf_patterns(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find SSRF patterns in the AST."""
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)

                # Check if this is an HTTP client function
                if self._is_http_client(func_text):
                    args = node.child_by_field_name("arguments")
                    if args:
                        full_call = self._get_node_text(node, source)
                        first_arg = self._get_first_argument(args, source)

                        # Get surrounding context first (needed for user input detection)
                        context = self._get_context(node, source, lines_before=10)

                        # Check if the URL argument appears to come from user input
                        if self._has_user_input(first_arg, full_call, context):
                            # Check surrounding context for validation
                            if not self._has_url_validation(context):
                                confidence = self._determine_confidence(first_arg, full_call, context)
                                matches.append(
                                    RuleMatch(
                                        line=node.start_point[0] + 1,
                                        column=node.start_point[1] + 1,
                                        end_line=node.end_point[0] + 1,
                                        end_column=node.end_point[1] + 1,
                                        matched_code=full_call[:200],  # Truncate long calls
                                        context={
                                            "function": func_text,
                                            "url_source": first_arg[:100] if first_arg else "unknown",
                                            "pattern": "user_controlled_url",
                                        },
                                        confidence_override=confidence,
                                    )
                                )

        for child in node.children:
            self._find_ssrf_patterns(child, source, matches)

    def _is_http_client(self, func_text: str) -> bool:
        """Check if the function is an HTTP client."""
        func_lower = func_text.lower()
        for client in self.HTTP_CLIENTS:
            if client.lower() in func_lower:
                return True
        return False

    def _get_first_argument(self, args_node: Node, source: str) -> str:
        """Extract the first argument from an arguments node."""
        for child in args_node.children:
            if child.type not in ["(", ")", ","]:
                return self._get_node_text(child, source)
        return ""

    def _has_user_input(self, arg: str, full_call: str, context: str = "") -> bool:
        """Check if the argument contains user input patterns.

        Args:
            arg: The first argument to the HTTP call
            full_call: The full call expression
            context: Surrounding code context (e.g., the containing function)

        Returns:
            True if user input is detected, False otherwise
        """
        text_to_check = arg + " " + full_call

        # First check direct patterns in the argument or call
        for pattern in self.USER_INPUT_PATTERNS:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return True

        # Check if argument is a variable (not a literal string starting with http/https)
        arg_stripped = arg.strip()
        is_literal_url = (
            arg_stripped.startswith('"http') or
            arg_stripped.startswith("'http") or
            arg_stripped.startswith('`http')
        )

        # If it's a variable, check if it's assigned from user input in the context
        if not is_literal_url and re.match(r'^[a-zA-Z_]\w*$', arg_stripped):
            # Check for variable assignment from user input sources in context
            # Pattern: const/let/var VARNAME = req.query/params/body...
            # Also matches: const VARNAME = req.body.field;
            if context:
                # Build pattern to find variable assignment from user input
                # Matches: const url = req.query.url; or let targetUrl = req.body.targetUrl;
                var_assignment_pattern = rf'\b(?:const|let|var)\s+{re.escape(arg_stripped)}\s*=\s*req\.(?:params|query|body)'
                if re.search(var_assignment_pattern, context, re.IGNORECASE):
                    return True

                # Also check for request.params/query/body patterns
                var_assignment_pattern = rf'\b(?:const|let|var)\s+{re.escape(arg_stripped)}\s*=\s*request\.(?:params|query|body)'
                if re.search(var_assignment_pattern, context, re.IGNORECASE):
                    return True

                # Check for ctx.params/query patterns (Koa framework)
                var_assignment_pattern = rf'\b(?:const|let|var)\s+{re.escape(arg_stripped)}\s*=\s*ctx\.(?:params|query)'
                if re.search(var_assignment_pattern, context, re.IGNORECASE):
                    return True

            # Common variable names that suggest user-controlled URLs
            risky_var_patterns = [
                r"url",
                r"uri",
                r"endpoint",
                r"target",
                r"host",
                r"destination",
                r"link",
                r"href",
                r"path",
                r"callback",
                r"webhook",
                r"redirect",
                r"external",
                r"remote",
                r"proxy",
            ]
            for var_pattern in risky_var_patterns:
                if re.search(var_pattern, arg_stripped, re.IGNORECASE):
                    return True

        # Check for template literals with substitutions
        if "${" in arg or "`" in arg:
            return True

        # Check for string concatenation
        if " + " in arg:
            return True

        return False

    def _has_url_validation(self, context: str) -> bool:
        """Check if there's URL validation in the surrounding context."""
        for pattern in self.SAFE_PATTERNS:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False

    def _get_context(self, node: Node, source: str, lines_before: int = 5) -> str:
        """Get surrounding context for a node, respecting function scope.

        This method tries to find the parent function scope and return only
        that context. If no parent function is found, falls back to line-based
        context.
        """
        # Try to find the parent function scope
        parent = node.parent
        while parent:
            if parent.type in ["function_declaration", "arrow_function", "function",
                             "method_definition", "function_signature"]:
                # Use the entire function scope as context
                func_start_line = parent.start_point[0]
                func_end_line = parent.end_point[0] + 1
                lines = source.split("\n")
                return "\n".join(lines[func_start_line:func_end_line])
            parent = parent.parent

        # Fallback to line-based context if no function scope found
        lines = source.split("\n")
        start_line = max(0, node.start_point[0] - lines_before)
        end_line = node.end_point[0] + 1
        return "\n".join(lines[start_line:end_line])

    def _determine_confidence(self, arg: str, full_call: str, context: str = "") -> Confidence:
        """Determine confidence level based on the nature of user input.

        Args:
            arg: The first argument to the HTTP call
            full_call: The full call expression
            context: Surrounding code context (e.g., the containing function)

        Returns:
            Confidence level (HIGH, MEDIUM, or LOW)
        """
        text_to_check = arg + " " + full_call

        # High confidence: Direct user input patterns in the call itself
        high_confidence_patterns = [
            r"req\.(?:params|query|body)",
            r"request\.(?:params|query|body)",
            r"ctx\.(?:params|query)",
            r"event\.(?:body|queryStringParameters)",
        ]
        for pattern in high_confidence_patterns:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return Confidence.HIGH

        # If argument is a variable, check if it's assigned from user input in context
        arg_stripped = arg.strip()
        is_literal_url = (
            arg_stripped.startswith('"http') or
            arg_stripped.startswith("'http") or
            arg_stripped.startswith('`http')
        )

        if not is_literal_url and re.match(r'^[a-zA-Z_]\w*$', arg_stripped) and context:
            # Check for variable assignment from user input sources in context
            # This indicates HIGH confidence because we can trace the data flow
            var_assignment_pattern = rf'\b(?:const|let|var)\s+{re.escape(arg_stripped)}\s*=\s*req\.(?:params|query|body)'
            if re.search(var_assignment_pattern, context, re.IGNORECASE):
                return Confidence.HIGH

            var_assignment_pattern = rf'\b(?:const|let|var)\s+{re.escape(arg_stripped)}\s*=\s*request\.(?:params|query|body)'
            if re.search(var_assignment_pattern, context, re.IGNORECASE):
                return Confidence.HIGH

            var_assignment_pattern = rf'\b(?:const|let|var)\s+{re.escape(arg_stripped)}\s*=\s*ctx\.(?:params|query)'
            if re.search(var_assignment_pattern, context, re.IGNORECASE):
                return Confidence.HIGH

        # Check for template literals with user input variables
        # Extract variable names from template literal ${varName}
        if "${" in arg and context:
            # Find all variables in the template literal
            template_vars = re.findall(r'\$\{([a-zA-Z_]\w*)', arg)
            for var_name in template_vars:
                # Check if any of these variables are assigned from user input
                var_assignment_pattern = rf'\b(?:const|let|var)\s+{re.escape(var_name)}\s*=\s*req\.(?:params|query|body)'
                if re.search(var_assignment_pattern, context, re.IGNORECASE):
                    return Confidence.HIGH

                var_assignment_pattern = rf'\b(?:const|let|var)\s+{re.escape(var_name)}\s*=\s*request\.(?:params|query|body)'
                if re.search(var_assignment_pattern, context, re.IGNORECASE):
                    return Confidence.HIGH

        # Medium confidence: Template literals or concatenation (without traced user input)
        if "${" in arg or " + " in arg:
            return Confidence.MEDIUM

        # Low confidence: Just variable names without clear user input tracing
        return Confidence.LOW
