"""Insecure deserialization detection rules for C#."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class InsecureDeserializationRule(Rule):
    """Detects usage of insecure deserialization methods."""

    rule_id = "CS-DESER-001"
    language = "csharp"
    vulnerability_type = VulnerabilityType.INSECURE_DESERIALIZATION
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe_id = "CWE-502"
    owasp_category = "A08:2021"

    title = "Insecure Deserialization Detected"
    description = (
        "The code uses a deserialization method that is known to be vulnerable to "
        "remote code execution attacks. Attackers can craft malicious serialized data "
        "to execute arbitrary code when deserialized."
    )
    remediation = (
        "1. Never use BinaryFormatter, it cannot be made safe\n"
        "2. Use JSON.NET with TypeNameHandling.None (default)\n"
        "3. Use DataContractSerializer with known types only\n"
        "4. Use System.Text.Json for modern .NET applications\n"
        "5. Validate and sanitize all input before deserialization"
    )

    DANGEROUS_FORMATTERS = [
        ("BinaryFormatter", "BinaryFormatter allows arbitrary code execution"),
        ("SoapFormatter", "SoapFormatter allows arbitrary code execution"),
        ("NetDataContractSerializer", "NetDataContractSerializer is unsafe with unknown types"),
        ("ObjectStateFormatter", "ObjectStateFormatter is vulnerable to RCE"),
        ("LosFormatter", "LosFormatter is vulnerable to RCE"),
        ("JavaScriptSerializer", "JavaScriptSerializer with type resolvers is dangerous"),
    ]

    DANGEROUS_PATTERNS = [
        (r"new\s+BinaryFormatter\s*\(\s*\)", "BinaryFormatter instantiation"),
        (r"\.Deserialize\s*\(", "Generic Deserialize call"),
        (r"BinaryFormatter\s*\.\s*Deserialize", "BinaryFormatter.Deserialize"),
        (r"SoapFormatter\s*\.\s*Deserialize", "SoapFormatter.Deserialize"),
        (r"TypeNameHandling\s*\.\s*All", "JSON.NET TypeNameHandling.All (dangerous)"),
        (r"TypeNameHandling\s*\.\s*Auto", "JSON.NET TypeNameHandling.Auto (dangerous)"),
        (r"TypeNameHandling\s*\.\s*Objects", "JSON.NET TypeNameHandling.Objects (dangerous)"),
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect insecure deserialization usage."""
        matches: list[RuleMatch] = []
        self._find_dangerous_formatters(tree.root_node, source, matches)
        self._find_dangerous_patterns(source, matches)
        return matches

    def _find_dangerous_formatters(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find dangerous formatter usage using AST."""
        if node.type == "object_creation_expression":
            text = self._get_node_text(node, source)

            for formatter, reason in self.DANGEROUS_FORMATTERS:
                if formatter in text:
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=self._get_node_text(node, source),
                            context={"formatter": formatter, "reason": reason},
                        )
                    )
                    break

        if node.type == "invocation_expression":
            text = self._get_node_text(node, source)

            for formatter, reason in self.DANGEROUS_FORMATTERS:
                if formatter in text and "Deserialize" in text:
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=self._get_node_text(node, source),
                            context={"formatter": formatter, "reason": reason},
                        )
                    )
                    break

        for child in node.children:
            self._find_dangerous_formatters(child, source, matches)

    def _find_dangerous_patterns(self, source: str, matches: list[RuleMatch]) -> None:
        """Find dangerous patterns using regex."""
        for pattern, description in self.DANGEROUS_PATTERNS:
            for match in re.finditer(pattern, source):
                line = source[:match.start()].count("\n") + 1
                matches.append(
                    RuleMatch(
                        line=line,
                        column=match.start() - source.rfind("\n", 0, match.start()),
                        matched_code=match.group(),
                        context={"pattern": description},
                    )
                )
