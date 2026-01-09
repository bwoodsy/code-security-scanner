"""Command and SQL injection detection rules for TypeScript/JavaScript."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.analysis.sources_sinks import is_safe_value
from securecode.analysis.taint import TaintTracker
from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

    from securecode.analysis.taint.tracker import TaintAnalysis


@register_rule
class CommandInjectionRule(Rule):
    """Detects potential command injection vulnerabilities."""

    rule_id = "TS-INJ-001"
    language = "typescript"
    vulnerability_type = VulnerabilityType.COMMAND_INJECTION
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe_id = "CWE-78"
    owasp_category = "A03:2021"

    title = "Potential Command Injection Vulnerability"
    description = (
        "The code executes shell commands with potentially user-controlled input. "
        "If the input is not properly sanitized, an attacker could inject arbitrary commands."
    )
    remediation = (
        "1. Avoid using shell commands when possible\n"
        "2. Use child_process.spawn with shell: false (default)\n"
        "3. Never use exec() with user-controlled input\n"
        "4. Use a library that handles escaping properly\n"
        "5. Validate and sanitize all inputs"
    )

    # exec/execSync ALWAYS use shell - very dangerous
    ALWAYS_DANGEROUS = ["exec", "execSync"]

    # spawn/spawnSync are only dangerous with shell: true
    DANGEROUS_WITH_SHELL = ["spawn", "spawnSync"]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect command injection vulnerabilities."""
        matches: list[RuleMatch] = []
        self._find_dangerous_exec(tree.root_node, source, matches)
        return matches

    def _find_dangerous_exec(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find dangerous exec/spawn calls."""
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)
                args = node.child_by_field_name("arguments")
                full_call = self._get_node_text(node, source)

                # Check for exec/execSync - these ALWAYS use shell
                for dangerous_func in self.ALWAYS_DANGEROUS:
                    if dangerous_func in func_text and "execFile" not in func_text:
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=full_call,
                                context={
                                    "function": dangerous_func,
                                    "reason": "exec always uses shell",
                                },
                            )
                        )
                        break

                # Check for spawn with shell: true (only dangerous pattern)
                for spawn_func in self.DANGEROUS_WITH_SHELL:
                    if spawn_func in func_text:
                        # Only flag if shell: true is present
                        if "shell: true" in full_call or "shell:true" in full_call:
                            matches.append(
                                RuleMatch(
                                    line=node.start_point[0] + 1,
                                    column=node.start_point[1] + 1,
                                    end_line=node.end_point[0] + 1,
                                    end_column=node.end_point[1] + 1,
                                    matched_code=full_call,
                                    context={
                                        "function": spawn_func,
                                        "reason": "shell: true enables command injection",
                                    },
                                )
                            )
                        break

        for child in node.children:
            self._find_dangerous_exec(child, source, matches)


@register_rule
class SQLInjectionRule(Rule):
    """Detects potential SQL injection vulnerabilities."""

    rule_id = "TS-SQL-001"
    language = "typescript"
    vulnerability_type = VulnerabilityType.SQL_INJECTION
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe_id = "CWE-89"
    owasp_category = "A03:2021"

    title = "Potential SQL Injection Vulnerability"
    description = (
        "The code constructs SQL queries using string concatenation or template literals "
        "with potentially user-controlled input. This can lead to SQL injection attacks."
    )
    remediation = (
        "1. Use parameterized queries or prepared statements\n"
        "2. Use an ORM with parameterized queries (TypeORM, Prisma, Sequelize)\n"
        "3. Never concatenate user input into SQL strings\n"
        "4. Use query builders that handle escaping"
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

    # Contexts that are NOT SQL-related (logging, error messages, etc.)
    SAFE_CONTEXTS = [
        "logger.", "console.", "log(", "warn(", "error(", "info(", "debug(",
        "Logger.", "Log.", "winston.", "pino.", "bunyan.",
        "throw new", "throw Error", "Error(",
        "reject(", "Promise.reject",
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect SQL injection vulnerabilities with taint analysis."""
        matches: list[RuleMatch] = []

        # Perform taint analysis on the entire file
        taint_tracker = TaintTracker(language="typescript")
        taint_analysis = taint_tracker.analyze(tree, source)

        # Find SQL injection patterns and use taint analysis to adjust confidence
        self._find_sql_injection(tree.root_node, source, matches, taint_analysis)
        return matches

    def _find_sql_injection(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
        taint_analysis: TaintAnalysis,
    ) -> None:
        """Find SQL injection patterns with taint-based confidence adjustment."""
        # Check template literals containing SQL
        if node.type == "template_string":
            text = self._get_node_text(node, source).upper()
            if any(keyword in text for keyword in self.SQL_KEYWORDS):
                # Check if it has substitutions
                has_substitution = any(
                    child.type == "template_substitution" for child in node.children
                )
                if has_substitution:
                    # Check surrounding context to filter out logging/error messages
                    context_start = max(0, node.start_byte - 100)
                    context_text = source[context_start:node.end_byte]

                    # Skip if this is in a logging/error context
                    if self._is_safe_context(context_text):
                        pass  # Skip this match
                    else:
                        # Analyze taint status of interpolated variables
                        taint_info = self._analyze_template_taint(
                            node, source, taint_analysis
                        )
                        confidence = self._determine_confidence(taint_info)

                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(node, source),
                                context={
                                    "pattern": "template_literal_sql",
                                    "taint_info": taint_info,
                                },
                                confidence_override=confidence,
                            )
                        )

        # Check string concatenation with SQL keywords
        if node.type == "binary_expression":
            left = node.child_by_field_name("left")
            operator = node.child_by_field_name("operator")
            if operator and self._get_node_text(operator, source) == "+":
                text = self._get_node_text(node, source).upper()
                if any(keyword in text for keyword in self.SQL_KEYWORDS):
                    # Check surrounding context
                    context_start = max(0, node.start_byte - 100)
                    context_text = source[context_start:node.end_byte]

                    if not self._is_safe_context(context_text):
                        # Analyze taint status of concatenated variables
                        taint_info = self._analyze_concatenation_taint(
                            node, source, taint_analysis
                        )
                        confidence = self._determine_confidence(taint_info)

                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(node, source),
                                context={
                                    "pattern": "string_concatenation_sql",
                                    "taint_info": taint_info,
                                },
                                confidence_override=confidence,
                            )
                        )

        # Check for dangerous ORM methods
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)
                dangerous_methods = [
                    "$queryRaw",
                    "$executeRaw",
                    "raw",
                    "query",
                    "execute",
                ]
                if any(method in func_text for method in dangerous_methods):
                    args = node.child_by_field_name("arguments")
                    if args and self._has_template_or_concat(args, source):
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(node, source),
                                context={"pattern": "orm_raw_query", "method": func_text},
                            )
                        )

        for child in node.children:
            self._find_sql_injection(child, source, matches)

    def _has_template_or_concat(self, node: Node, source: str) -> bool:
        """Check if node contains template literals or concatenation."""
        if node.type in ["template_string", "binary_expression"]:
            return True
        for child in node.children:
            if self._has_template_or_concat(child, source):
                return True
        return False

    def _is_safe_context(self, context_text: str) -> bool:
        """Check if the code is in a safe context (logging, error handling)."""
        context_lower = context_text.lower()
        for safe_pattern in self.SAFE_CONTEXTS:
            if safe_pattern.lower() in context_lower:
                return True
        return False
