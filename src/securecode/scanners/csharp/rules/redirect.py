"""Open redirect detection rules for C#."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class OpenRedirectRule(Rule):
    """Detects potential open redirect vulnerabilities in C# code."""

    rule_id = "CS-REDIR-001"
    language = "csharp"
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
        "1. Use Url.IsLocalUrl() to validate redirect URLs\n"
        "2. Use LocalRedirect() instead of Redirect() in ASP.NET Core\n"
        "3. Maintain a whitelist of allowed redirect destinations\n"
        "4. Only allow relative URLs for redirects"
    )

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect open redirect vulnerabilities."""
        matches: list[RuleMatch] = []
        self._find_unsafe_redirects(tree.root_node, source, matches)
        self._find_redirect_patterns(source, matches)
        return matches

    def _find_unsafe_redirects(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find redirects with potentially user-controlled URLs."""
        if node.type == "invocation_expression":
            text = self._get_node_text(node, source)

            # ASP.NET Core/MVC Redirect methods
            redirect_methods = [
                "Redirect(", "RedirectPermanent(",
                "RedirectToAction(", "RedirectToRoute(",
                "RedirectToPage(",
            ]

            for method in redirect_methods:
                if method in text:
                    # Check if the argument looks like user input
                    if self._has_user_controlled_url(text):
                        # Ignore if it's LocalRedirect
                        if "LocalRedirect" in text:
                            break

                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=text[:150],
                                context={"method": method.rstrip("("), "type": "mvc_redirect"},
                            )
                        )
                    break

            # Response.Redirect
            if "Response.Redirect" in text:
                if self._has_user_controlled_url(text):
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=text[:150],
                            context={"method": "Response.Redirect", "type": "webforms_redirect"},
                        )
                    )

        for child in node.children:
            self._find_unsafe_redirects(child, source, matches)

    def _find_redirect_patterns(self, source: str, matches: list[RuleMatch]) -> None:
        """Find redirect patterns using regex."""
        lines = source.split("\n")

        # Patterns for unsafe redirects
        patterns = [
            # Redirect with request parameter
            (r'Redirect\s*\(\s*Request\[', "Redirect with Request parameter"),
            (r'Redirect\s*\(\s*Request\.QueryString', "Redirect with query string"),
            # Return redirect with model/viewdata
            (r'return\s+Redirect\s*\([^)]*returnUrl', "Redirect with returnUrl parameter"),
            (r'return\s+Redirect\s*\([^)]*redirect', "Redirect with redirect parameter"),
        ]

        for pattern, description in patterns:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line = source[:match.start()].count("\n") + 1
                line_content = lines[line - 1] if line <= len(lines) else ""

                if line_content.strip().startswith("//"):
                    continue

                matches.append(
                    RuleMatch(
                        line=line,
                        column=match.start() - source.rfind("\n", 0, match.start()),
                        matched_code=match.group()[:100],
                        context={"description": description},
                    )
                )

    def _has_user_controlled_url(self, text: str) -> bool:
        """Check if redirect uses user-controlled URL."""
        user_input_patterns = [
            "Request[", "Request.", "HttpContext",
            "QueryString", "Form[",
            "returnUrl", "redirectUrl", "redirect_uri",
            "returnTo", "next", "goto", "target", "url",
            "model.", "Model.",
        ]

        text_lower = text.lower()
        return any(p.lower() in text_lower for p in user_input_patterns)


@register_rule
class InsecureCookieRule(Rule):
    """Detects insecure cookie configurations."""

    rule_id = "CS-COOKIE-001"
    language = "csharp"
    vulnerability_type = VulnerabilityType.INSECURE_COOKIE
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    cwe_id = "CWE-614"
    owasp_category = "A05:2021"

    title = "Insecure Cookie Configuration"
    description = (
        "The code creates cookies without proper security attributes. "
        "Cookies should have HttpOnly, Secure, and SameSite attributes set."
    )
    remediation = (
        "1. Set HttpOnly = true to prevent XSS access\n"
        "2. Set Secure = true to only send over HTTPS\n"
        "3. Set SameSite = SameSiteMode.Strict or Lax\n"
        "4. Use authentication cookies with proper settings"
    )

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect insecure cookie configurations."""
        matches: list[RuleMatch] = []
        self._find_insecure_cookies(source, matches)
        return matches

    def _find_insecure_cookies(self, source: str, matches: list[RuleMatch]) -> None:
        """Find insecure cookie patterns."""
        lines = source.split("\n")

        # Check for cookies without HttpOnly
        patterns = [
            (r'new\s+Cookie\s*\([^)]+\)\s*;', "Cookie without security attributes"),
            (r'Response\.Cookies\.Append\s*\([^)]+\)\s*;', "Cookie append without options"),
            (r'HttpOnly\s*=\s*false', "HttpOnly disabled"),
            (r'Secure\s*=\s*false', "Secure flag disabled"),
        ]

        for pattern, description in patterns:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line = source[:match.start()].count("\n") + 1
                line_content = lines[line - 1] if line <= len(lines) else ""

                if line_content.strip().startswith("//"):
                    continue

                # Check context for security settings
                context_end = min(len(source), match.end() + 200)
                context = source[match.start():context_end]

                # Skip if HttpOnly and Secure are set in the context
                if "HttpOnly = true" in context and "Secure = true" in context:
                    continue

                matches.append(
                    RuleMatch(
                        line=line,
                        column=match.start() - source.rfind("\n", 0, match.start()),
                        matched_code=match.group()[:100],
                        context={"description": description},
                    )
                )
