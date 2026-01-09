"""XXE (XML External Entity) detection rules for C#."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class XXERule(Rule):
    """Detects potential XML External Entity (XXE) vulnerabilities."""

    rule_id = "CS-XXE-001"
    language = "csharp"
    vulnerability_type = VulnerabilityType.XXE
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe_id = "CWE-611"
    owasp_category = "A05:2021"

    title = "Potential XML External Entity (XXE) Vulnerability"
    description = (
        "The code parses XML with settings that may allow external entity processing. "
        "An attacker could read sensitive files or perform SSRF attacks."
    )
    remediation = (
        "1. Set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit\n"
        "2. Set XmlReaderSettings.XmlResolver = null\n"
        "3. Use XDocument with safe settings\n"
        "4. Disable DTD processing in XmlDocument\n"
        "5. Use XmlReader.Create() with secure settings"
    )

    # Dangerous XML parsing patterns
    DANGEROUS_PATTERNS = [
        # XmlDocument with DTD
        (r"new\s+XmlDocument\s*\(\s*\)", "XmlDocument with default settings"),
        # XmlTextReader (deprecated and unsafe by default)
        (r"new\s+XmlTextReader\s*\(", "XmlTextReader is unsafe by default"),
        # DtdProcessing.Parse
        (r"DtdProcessing\s*\.\s*Parse", "DTD processing enabled"),
        # XmlResolver not null
        (r"XmlResolver\s*=\s*new\s+Xml", "Custom XmlResolver may allow external entities"),
        # ProhibitDtd = false (old API)
        (r"ProhibitDtd\s*=\s*false", "DTD processing enabled"),
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect XXE vulnerabilities."""
        matches: list[RuleMatch] = []

        # Check for dangerous patterns
        self._find_dangerous_xml_patterns(source, matches)

        # Check AST for unsafe XML usage
        self._find_unsafe_xml_usage(tree.root_node, source, matches)

        return matches

    def _find_dangerous_xml_patterns(self, source: str, matches: list[RuleMatch]) -> None:
        """Find dangerous XML patterns using regex."""
        lines = source.split("\n")

        for pattern, description in self.DANGEROUS_PATTERNS:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line = source[:match.start()].count("\n") + 1

                # Skip comments
                line_content = lines[line - 1] if line <= len(lines) else ""
                if line_content.strip().startswith("//"):
                    continue

                matches.append(
                    RuleMatch(
                        line=line,
                        column=match.start() - source.rfind("\n", 0, match.start()),
                        matched_code=match.group(),
                        context={"description": description, "pattern": pattern},
                    )
                )

    def _find_unsafe_xml_usage(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find unsafe XML usage patterns in AST."""
        # Check for XmlDocument.Load, XmlDocument.LoadXml
        if node.type == "invocation_expression":
            text = self._get_node_text(node, source)

            # XmlDocument.Load or LoadXml without safe settings
            if ".Load" in text or ".LoadXml" in text:
                if "XmlDocument" in text or "xmlDoc" in text.lower():
                    # Check if there's XmlResolver = null or DtdProcessing.Prohibit nearby
                    context_start = max(0, node.start_byte - 500)
                    context = source[context_start:node.end_byte]

                    is_safe = (
                        "XmlResolver = null" in context
                        or "DtdProcessing.Prohibit" in context
                        or "DtdProcessing = DtdProcessing.Prohibit" in context
                    )

                    if not is_safe:
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=text[:100],
                                context={"method": "Load/LoadXml", "type": "XmlDocument"},
                            )
                        )

        for child in node.children:
            self._find_unsafe_xml_usage(child, source, matches)
