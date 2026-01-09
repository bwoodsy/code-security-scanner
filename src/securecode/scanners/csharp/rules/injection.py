"""SQL and Command injection detection rules for C#."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class SQLInjectionRule(Rule):
    """Detects potential SQL injection vulnerabilities in C# code."""

    rule_id = "CS-SQL-001"
    language = "csharp"
    vulnerability_type = VulnerabilityType.SQL_INJECTION
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe_id = "CWE-89"
    owasp_category = "A03:2021"

    title = "Potential SQL Injection Vulnerability"
    description = (
        "The code constructs SQL queries using string concatenation or interpolation "
        "with potentially user-controlled input. This can lead to SQL injection attacks."
    )
    remediation = (
        "1. Use parameterized queries with SqlParameter\n"
        "2. Use Entity Framework with LINQ queries\n"
        "3. Use stored procedures with parameters\n"
        "4. Never concatenate user input into SQL strings"
    )

    SQL_KEYWORDS = [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "CREATE",
        "ALTER",
        "TRUNCATE",
        "EXEC",
        "EXECUTE",
    ]

    DANGEROUS_METHODS = [
        "ExecuteSqlRaw",
        "FromSqlRaw",
        "ExecuteSqlCommand",
        "ExecuteNonQuery",
        "ExecuteReader",
        "ExecuteScalar",
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect SQL injection vulnerabilities."""
        matches: list[RuleMatch] = []
        self._find_sql_injection(tree.root_node, source, matches)
        self._find_sql_injection_regex(source, matches)
        return matches

    def _find_sql_injection(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find SQL injection patterns using AST."""
        # Check interpolated strings containing SQL
        if node.type == "interpolated_string_expression":
            text = self._get_node_text(node, source).upper()
            if any(keyword in text for keyword in self.SQL_KEYWORDS):
                # Has interpolation with SQL keywords
                matches.append(
                    RuleMatch(
                        line=node.start_point[0] + 1,
                        column=node.start_point[1] + 1,
                        end_line=node.end_point[0] + 1,
                        end_column=node.end_point[1] + 1,
                        matched_code=self._get_node_text(node, source),
                        context={"pattern": "interpolated_string_sql"},
                    )
                )

        # Check string concatenation with SQL keywords
        if node.type == "binary_expression":
            text = self._get_node_text(node, source).upper()
            if any(keyword in text for keyword in self.SQL_KEYWORDS):
                if "+" in self._get_node_text(node, source):
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=self._get_node_text(node, source),
                            context={"pattern": "string_concatenation_sql"},
                        )
                    )

        # Check for dangerous method calls
        if node.type == "invocation_expression":
            text = self._get_node_text(node, source)
            for method in self.DANGEROUS_METHODS:
                if method in text:
                    # Check if the argument is a variable or interpolated string
                    args = node.child_by_field_name("arguments")
                    if args:
                        args_text = self._get_node_text(args, source)
                        if "$" in args_text or "+" in args_text:
                            matches.append(
                                RuleMatch(
                                    line=node.start_point[0] + 1,
                                    column=node.start_point[1] + 1,
                                    end_line=node.end_point[0] + 1,
                                    end_column=node.end_point[1] + 1,
                                    matched_code=self._get_node_text(node, source),
                                    context={"method": method, "pattern": "dangerous_method"},
                                )
                            )
                    break

        for child in node.children:
            self._find_sql_injection(child, source, matches)

    def _find_sql_injection_regex(self, source: str, matches: list[RuleMatch]) -> None:
        """Find SQL injection patterns using regex (hybrid approach)."""
        # Pattern for SqlCommand with string concatenation
        pattern = r'new\s+SqlCommand\s*\([^)]*\+[^)]*\)'
        for match in re.finditer(pattern, source, re.IGNORECASE):
            line = source[:match.start()].count("\n") + 1
            matches.append(
                RuleMatch(
                    line=line,
                    column=match.start() - source.rfind("\n", 0, match.start()),
                    matched_code=match.group()[:100],
                    context={"pattern": "regex_sqlcommand_concat"},
                )
            )


@register_rule
class CommandInjectionRule(Rule):
    """Detects potential command injection vulnerabilities in C# code."""

    rule_id = "CS-INJ-001"
    language = "csharp"
    vulnerability_type = VulnerabilityType.COMMAND_INJECTION
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe_id = "CWE-78"
    owasp_category = "A03:2021"

    title = "Potential Command Injection Vulnerability"
    description = (
        "The code executes system commands with potentially user-controlled input. "
        "This can allow attackers to execute arbitrary commands on the system."
    )
    remediation = (
        "1. Avoid using Process.Start with user-controlled input\n"
        "2. Use a whitelist of allowed commands\n"
        "3. Sanitize and validate all input\n"
        "4. Use ProcessStartInfo with UseShellExecute = false"
    )

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect command injection vulnerabilities."""
        matches: list[RuleMatch] = []
        self._find_process_start(tree.root_node, source, matches)
        return matches

    def _find_process_start(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find Process.Start and similar calls."""
        if node.type == "invocation_expression":
            text = self._get_node_text(node, source)

            # Check for Process.Start
            if "Process.Start" in text or "ProcessStartInfo" in text:
                # Check if arguments contain variables or interpolation
                args = node.child_by_field_name("arguments")
                if args:
                    args_text = self._get_node_text(args, source)
                    # Look for dangerous shells
                    if any(shell in args_text.lower() for shell in ["cmd", "powershell", "bash", "sh"]):
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(node, source),
                                context={"pattern": "shell_execution"},
                            )
                        )
                    # Check for variable arguments
                    elif "$" in args_text or "+" in args_text:
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(node, source),
                                context={"pattern": "dynamic_arguments"},
                            )
                        )

        for child in node.children:
            self._find_process_start(child, source, matches)
