"""Prototype pollution detection rules for TypeScript/JavaScript."""

from __future__ import annotations

from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class PrototypePollutionRule(Rule):
    """Detects potential prototype pollution vulnerabilities."""

    rule_id = "TS-PROTO-001"
    language = "typescript"
    vulnerability_type = VulnerabilityType.CODE_INJECTION
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    cwe_id = "CWE-1321"
    owasp_category = "A03:2021"

    title = "Potential Prototype Pollution Vulnerability"
    description = (
        "The code performs deep object merging or property assignment that could allow "
        "an attacker to inject properties into Object.prototype, affecting all objects."
    )
    remediation = (
        "1. Use Object.create(null) for objects used as maps\n"
        "2. Validate that keys are not '__proto__', 'constructor', or 'prototype'\n"
        "3. Use Map instead of plain objects for user-controlled keys\n"
        "4. Use libraries with prototype pollution protection (lodash >= 4.17.12)\n"
        "5. Freeze Object.prototype in sensitive contexts"
    )

    # Functions known to be vulnerable to prototype pollution
    DANGEROUS_MERGE_FUNCTIONS = [
        "merge", "deepMerge", "extend", "deepExtend",
        "assign", "deepAssign", "defaults", "defaultsDeep",
        "set", "setWith",  # lodash set with user-controlled path
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect prototype pollution vulnerabilities."""
        matches: list[RuleMatch] = []
        self._find_dangerous_merge(tree.root_node, source, matches)
        self._find_bracket_assignment(tree.root_node, source, matches)
        return matches

    def _find_dangerous_merge(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find dangerous deep merge operations."""
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)

                for merge_func in self.DANGEROUS_MERGE_FUNCTIONS:
                    # Check for _.merge, lodash.merge, etc.
                    if f".{merge_func}" in func_text or func_text == merge_func:
                        args = node.child_by_field_name("arguments")
                        if args:
                            args_text = self._get_node_text(args, source)
                            # Check if merging user input
                            if self._looks_like_user_input(args_text):
                                matches.append(
                                    RuleMatch(
                                        line=node.start_point[0] + 1,
                                        column=node.start_point[1] + 1,
                                        end_line=node.end_point[0] + 1,
                                        end_column=node.end_point[1] + 1,
                                        matched_code=self._get_node_text(node, source),
                                        context={
                                            "function": merge_func,
                                            "type": "deep_merge",
                                        },
                                    )
                                )
                        break

        for child in node.children:
            self._find_dangerous_merge(child, source, matches)

    def _find_bracket_assignment(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find bracket notation assignments with user-controlled keys."""
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left and left.type == "subscript_expression":
                # Get the key being used
                key_text = ""
                for child in left.children:
                    if child.type not in ["[", "]", "identifier", "member_expression"]:
                        key_text = self._get_node_text(child, source)
                        break

                # Check for nested bracket notation like obj[a][b] = value
                left_text = self._get_node_text(left, source)
                if left_text.count("[") >= 2 and self._looks_like_user_input(left_text):
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=self._get_node_text(node, source),
                            context={
                                "type": "nested_bracket_assignment",
                            },
                        )
                    )

        for child in node.children:
            self._find_bracket_assignment(child, source, matches)

    def _looks_like_user_input(self, text: str) -> bool:
        """Check if text looks like it contains user input."""
        user_input_patterns = [
            "req.body", "req.query", "req.params",
            "request.body", "request.query", "request.params",
            "ctx.body", "ctx.query", "ctx.params",
            "body.", "query.", "params.",
            "userInput", "userData", "payload",
        ]
        return any(pattern in text for pattern in user_input_patterns)
