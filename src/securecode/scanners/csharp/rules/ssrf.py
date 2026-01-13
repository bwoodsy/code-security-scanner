"""Server-Side Request Forgery (SSRF) detection rules for C#."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class SSRFRule(Rule):
    """Detects potential Server-Side Request Forgery vulnerabilities in C# code."""

    rule_id = "CS-SSRF-001"
    language = "csharp"
    vulnerability_type = VulnerabilityType.SSRF
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    cwe_id = "CWE-918"
    owasp_category = "A10:2021"

    title = "Potential Server-Side Request Forgery (SSRF)"
    description = (
        "The code makes HTTP requests to URLs that may be controlled by user input. "
        "An attacker could use this to access internal services, read sensitive data, "
        "bypass authentication, or perform actions on behalf of the server. SSRF can "
        "be used to scan internal networks, access cloud metadata endpoints, or "
        "exploit trust relationships."
    )
    remediation = (
        "1. Validate and sanitize all URL inputs using Uri.TryCreate() and Uri.IsWellFormedUriString()\n"
        "2. Use an allowlist of permitted domains/hosts\n"
        "3. Block requests to internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)\n"
        "4. Use Uri class to parse and validate the scheme and host before making requests\n"
        "5. Prefer configuration-based URLs (IConfiguration) over user-supplied URLs\n"
        "6. Implement DNS validation to prevent bypasses via DNS rebinding\n"
        "7. Disable or restrict HTTP redirects when processing user-supplied URLs"
    )

    # HTTP client methods that can be SSRF vectors
    # Note: We match method names, not full qualified names, since HttpClient
    # instances may have various variable names (_httpClient, client, etc.)
    HTTP_CLIENT_METHODS = [
        "GetAsync",
        "PostAsync",
        "PutAsync",
        "DeleteAsync",
        "SendAsync",
        "GetStringAsync",
        "GetByteArrayAsync",
        "GetStreamAsync",
        "DownloadString",
        "DownloadData",
        "DownloadFile",
        "UploadString",
        "UploadData",
        "WebRequest.Create",
        "HttpWebRequest.Create",
        "RestClient.Execute",
        "RestClient.Get",
        "RestClient.Post",
        "HttpRequestMessage",
    ]

    # User input sources in ASP.NET/ASP.NET Core
    USER_INPUT_PATTERNS = [
        r"Request\.Query\[",
        r"Request\.Form\[",
        r"Request\.Headers\[",
        r"Request\.QueryString",
        r"HttpContext\.Request",
        r"\[FromQuery\]",
        r"\[FromBody\]",
        r"\[FromRoute\]",
        r"\[FromHeader\]",
        r"\[FromForm\]",
        r"RouteData\.Values",
        r"ControllerContext\.RouteData",
        r"QueryString\.Value",
        r"\.Query\.Get",
        r"\.Form\.Get",
    ]

    # Safe patterns that indicate URL validation/sanitization
    SAFE_PATTERNS = [
        r"Uri\.IsWellFormedUriString\s*\(",
        r"Uri\.TryCreate\s*\(",
        r"\ballowlist\b",
        r"\bwhitelist\b",
        r"\ballowedHosts\b",
        r"\ballowedDomains\b",
        r"\bvalidHosts\b",
        r"\bisValidUrl\s*\(",
        r"\bvalidateUrl\s*\(",
        r"\.Host\s*==",
        r"\.Authority\s*==",
        r"IConfiguration",
        r"_configuration\[",
        r"Configuration\[",
        r"\.Contains\s*\(\s*.*\.Host",
        r"\.Any\s*\(\s*.*\.Host",
        r"IsLocalUrl\s*\(",
        r"Url\.IsLocalUrl\s*\(",
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect SSRF vulnerabilities."""
        matches: list[RuleMatch] = []
        self._find_ssrf_patterns(tree.root_node, source, matches)
        self._find_ssrf_regex_patterns(source, matches)
        return matches

    def _find_ssrf_patterns(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find SSRF patterns using AST traversal."""
        if node.type == "invocation_expression":
            full_call = self._get_node_text(node, source)

            # Check if this is an HTTP client method call
            if self._is_http_client_call(full_call):
                # Get the URL argument
                url_arg = self._extract_url_argument(node, source)

                if url_arg and self._has_user_input(url_arg, full_call):
                    # Check surrounding context for validation
                    context = self._get_context(node, source, lines_before=15)

                    if not self._has_url_validation(context):
                        confidence = self._determine_confidence(url_arg, full_call, context)

                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=full_call[:200],
                                context={
                                    "url_source": url_arg[:100] if url_arg else "unknown",
                                    "pattern": "user_controlled_url",
                                    "method": self._extract_method_name(full_call),
                                },
                                confidence_override=confidence,
                            )
                        )

        # Check for HttpRequestMessage constructor with user input
        if node.type == "object_creation_expression":
            text = self._get_node_text(node, source)
            if "HttpRequestMessage" in text:
                if self._has_user_input_in_node(node, source):
                    context = self._get_context(node, source, lines_before=15)
                    if not self._has_url_validation(context):
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=text[:200],
                                context={
                                    "pattern": "http_request_message_user_input",
                                    "type": "object_creation",
                                },
                            )
                        )

        for child in node.children:
            self._find_ssrf_patterns(child, source, matches)

    def _find_ssrf_regex_patterns(self, source: str, matches: list[RuleMatch]) -> None:
        """Find SSRF patterns using regex for patterns hard to detect with AST."""
        lines = source.split("\n")

        # Pattern: WebRequest.Create with user input
        patterns = [
            (r"WebRequest\.Create\s*\(\s*Request\.", "WebRequest.Create with Request"),
            (r"HttpWebRequest\.Create\s*\(\s*Request\.", "HttpWebRequest.Create with Request"),
            (r"new\s+Uri\s*\(\s*Request\.", "Uri constructor with Request"),
        ]

        for pattern, description in patterns:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line = source[:match.start()].count("\n") + 1
                line_content = lines[line - 1] if line <= len(lines) else ""

                # Skip comments
                if line_content.strip().startswith("//"):
                    continue

                # Check context for validation
                context_start = max(0, match.start() - 500)
                context_end = min(len(source), match.end() + 500)
                context = source[context_start:context_end]

                if not self._has_url_validation(context):
                    matches.append(
                        RuleMatch(
                            line=line,
                            column=match.start() - source.rfind("\n", 0, match.start()),
                            matched_code=match.group()[:100],
                            context={"description": description, "pattern": "regex_detection"},
                        )
                    )

    def _is_http_client_call(self, call_text: str) -> bool:
        """Check if the call is an HTTP client method."""
        for method in self.HTTP_CLIENT_METHODS:
            if method in call_text:
                return True
        return False

    def _extract_method_name(self, call_text: str) -> str:
        """Extract the method name from the call text."""
        for method in self.HTTP_CLIENT_METHODS:
            if method in call_text:
                return method
        return "unknown"

    def _extract_url_argument(self, node: Node, source: str) -> str:
        """Extract the URL argument from an HTTP client call."""
        # In C# tree-sitter, arguments are in argument_list node
        for child in node.children:
            if child.type == "argument_list":
                # Get first argument
                for arg_child in child.children:
                    if arg_child.type == "argument":
                        # The argument may contain an identifier or more complex expression
                        return self._get_node_text(arg_child, source)
        return ""

    def _has_user_input(self, arg: str, full_call: str) -> bool:
        """Check if the argument or call contains user input patterns."""
        text_to_check = arg + " " + full_call

        # Check for explicit user input patterns
        for pattern in self.USER_INPUT_PATTERNS:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return True

        # Check if argument is a variable (not a literal string starting with http/https)
        arg_stripped = arg.strip()
        is_literal_url = (
            arg_stripped.startswith('"http') or
            arg_stripped.startswith("'http") or
            arg_stripped.startswith('@"http')
        )

        # If it's a variable, check for risky variable names
        if not is_literal_url and re.match(r'^[a-zA-Z_]\w*$', arg_stripped):
            risky_var_patterns = [
                r"\burl\b",
                r"\buri\b",
                r"\bendpoint\b",
                r"\btarget\b",
                r"\btargetUrl\b",
                r"\bhost\b",
                r"\bdestination\b",
                r"\blink\b",
                r"\bhref\b",
                r"\bpath\b",
                r"\bcallback\b",
                r"\bwebhook\b",
                r"\bredirect\b",
                r"\bexternal\b",
                r"\bremote\b",
                r"\bproxy\b",
                r"\bapiUrl\b",
                r"\bbaseUrl\b",
                r"\bserviceUrl\b",
            ]
            for var_pattern in risky_var_patterns:
                if re.search(var_pattern, arg_stripped, re.IGNORECASE):
                    return True

        # Check for string interpolation
        if "$" in arg or "{" in arg:
            return True

        # Check for string concatenation
        if " + " in arg:
            return True

        return False

    def _has_user_input_in_node(self, node: Node, source: str) -> bool:
        """Check if a node contains user input patterns."""
        text = self._get_node_text(node, source)
        for pattern in self.USER_INPUT_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _has_url_validation(self, context: str) -> bool:
        """Check if there's URL validation in the surrounding context."""
        for pattern in self.SAFE_PATTERNS:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False

    def _get_context(self, node: Node, source: str, lines_before: int = 10) -> str:
        """Get surrounding context for a node, respecting method/class scope.

        This method tries to find the parent method/class scope and return only
        that context. If no parent scope is found, falls back to line-based context.
        """
        # Try to find the parent method or class scope
        parent = node.parent
        while parent:
            if parent.type in [
                "method_declaration",
                "constructor_declaration",
                "local_function_statement",
                "lambda_expression",
                "class_declaration",
            ]:
                # Use the entire method/class scope as context
                scope_start_line = parent.start_point[0]
                scope_end_line = parent.end_point[0] + 1
                lines = source.split("\n")
                return "\n".join(lines[scope_start_line:scope_end_line])
            parent = parent.parent

        # Fallback to line-based context if no scope found
        lines = source.split("\n")
        start_line = max(0, node.start_point[0] - lines_before)
        end_line = node.end_point[0] + 1
        return "\n".join(lines[start_line:end_line])

    def _determine_confidence(self, arg: str, full_call: str, context: str = "") -> Confidence:
        """Determine confidence level based on the nature of user input.

        Args:
            arg: The URL argument
            full_call: The full HTTP call expression
            context: Surrounding code context

        Returns:
            Confidence level (HIGH, MEDIUM, or LOW)
        """
        text_to_check = arg + " " + full_call + " " + context

        # High confidence: Direct ASP.NET request input patterns
        high_confidence_patterns = [
            r"Request\.Query\[",
            r"Request\.Form\[",
            r"Request\.Headers\[",
            r"Request\.QueryString",
            r"\[FromQuery\]",
            r"\[FromBody\]",
            r"\[FromRoute\]",
            r"HttpContext\.Request",
        ]
        for pattern in high_confidence_patterns:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return Confidence.HIGH

        # Medium confidence: String interpolation or concatenation
        if "$" in arg or " + " in arg or "{" in arg:
            return Confidence.MEDIUM

        # Medium confidence: Action parameter with risky name
        if re.search(r"\b(url|uri|target|endpoint|callback|webhook)\b", arg, re.IGNORECASE):
            return Confidence.MEDIUM

        # Low confidence: Generic variable names
        return Confidence.LOW
