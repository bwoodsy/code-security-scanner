"""LDAP injection detection rules for C#."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class LDAPInjectionRule(Rule):
    """Detects potential LDAP injection vulnerabilities."""

    rule_id = "CS-LDAP-001"
    language = "csharp"
    vulnerability_type = VulnerabilityType.LDAP_INJECTION
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe_id = "CWE-90"
    owasp_category = "A03:2021"

    title = "Potential LDAP Injection Vulnerability"
    description = (
        "The code constructs LDAP queries using string concatenation with potentially "
        "user-controlled input. An attacker could modify the query to bypass authentication "
        "or access unauthorized data."
    )
    remediation = (
        "1. Use parameterized LDAP queries\n"
        "2. Escape special LDAP characters: * ( ) \\ NUL\n"
        "3. Use a whitelist of allowed characters\n"
        "4. Validate input against expected patterns"
    )

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect LDAP injection vulnerabilities."""
        matches: list[RuleMatch] = []
        self._find_ldap_injection(source, matches)
        self._find_ldap_in_ast(tree.root_node, source, matches)
        return matches

    def _find_ldap_injection(self, source: str, matches: list[RuleMatch]) -> None:
        """Find LDAP injection patterns using regex."""
        lines = source.split("\n")

        # Patterns for LDAP filter construction
        patterns = [
            # DirectorySearcher.Filter with concatenation
            (r'\.Filter\s*=\s*["\']?\s*\([^)]*\$?\{', "LDAP filter with interpolation"),
            (r'\.Filter\s*=\s*[^;]*\+', "LDAP filter with string concatenation"),
            # String.Format in LDAP context
            (r'String\.Format\s*\(\s*"[^"]*\([^)]*\{0\}', "LDAP filter with String.Format"),
            # Common LDAP filter patterns with variables
            (r'\(\s*[a-zA-Z]+\s*=\s*\{', "LDAP filter with variable"),
            (r'\(\s*[a-zA-Z]+\s*=\s*"\s*\+', "LDAP filter concatenation"),
        ]

        for pattern, description in patterns:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line = source[:match.start()].count("\n") + 1
                line_content = lines[line - 1] if line <= len(lines) else ""

                # Skip comments
                if line_content.strip().startswith("//"):
                    continue

                # Only flag if in LDAP context
                context_start = max(0, match.start() - 200)
                context = source[context_start:match.end() + 100]
                if any(kw in context for kw in ["DirectorySearcher", "DirectoryEntry", "LDAP", "ldap"]):
                    matches.append(
                        RuleMatch(
                            line=line,
                            column=match.start() - source.rfind("\n", 0, match.start()),
                            matched_code=match.group()[:80],
                            context={"description": description},
                        )
                    )

    def _find_ldap_in_ast(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find LDAP injection patterns in AST."""
        if node.type == "assignment_expression":
            text = self._get_node_text(node, source)

            # Check for Filter property assignment with dynamic values
            if ".Filter" in text:
                # Check for string concatenation or interpolation
                if "+" in text or "${" in text or "{" in text:
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=text[:100],
                            context={"type": "filter_assignment"},
                        )
                    )

        for child in node.children:
            self._find_ldap_in_ast(child, source, matches)
