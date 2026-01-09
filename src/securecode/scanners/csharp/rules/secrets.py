"""Hardcoded secrets detection rules for C#."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class HardcodedSecretsRule(Rule):
    """Detects hardcoded secrets, connection strings, and credentials in C# code."""

    rule_id = "CS-SEC-001"
    language = "csharp"
    vulnerability_type = VulnerabilityType.HARDCODED_SECRET
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe_id = "CWE-798"
    owasp_category = "A07:2021"

    title = "Hardcoded Secret or Credential Detected"
    description = (
        "The code contains what appears to be a hardcoded secret, password, or connection string. "
        "Hardcoded credentials can be extracted from compiled assemblies and exploited."
    )
    remediation = (
        "1. Use Azure Key Vault or similar secrets manager\n"
        "2. Use environment variables via Configuration\n"
        "3. Use User Secrets for development\n"
        "4. Use appsettings.json with secrets excluded from source control\n"
        "5. Rotate any exposed credentials immediately"
    )

    # Variable name patterns that suggest secrets
    SECRET_NAME_PATTERNS = [
        r"(?i)(password|passwd|pwd)",
        r"(?i)(secret)",
        r"(?i)(api[_-]?key|apikey)",
        r"(?i)(access[_-]?key|accesskey)",
        r"(?i)(auth[_-]?token)",
        r"(?i)(private[_-]?key)",
        r"(?i)(connection[_-]?string)",
        r"(?i)(credentials?)",
        r"(?i)(encryption[_-]?key)",
    ]

    # Value patterns that indicate secrets
    SECRET_VALUE_PATTERNS = [
        # Connection strings with passwords
        (r"(?i)password\s*=\s*['\"][^'\"]+['\"]", "Connection string password"),
        (r"(?i)pwd\s*=\s*['\"][^'\"]+['\"]", "Connection string password"),
        # Azure connection strings
        (r"AccountKey=[A-Za-z0-9+/=]{40,}", "Azure Storage Account Key"),
        (r"SharedAccessSignature=", "Azure SAS Token"),
        # AWS keys
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        # Private keys
        (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private Key"),
        # Generic long secrets
        (r"['\"][A-Za-z0-9+/]{40,}={0,2}['\"]", "Potential Base64 Secret"),
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect hardcoded secrets."""
        matches: list[RuleMatch] = []
        self._find_secret_assignments(tree.root_node, source, matches)
        self._find_secret_patterns(source, matches)
        return matches

    def _find_secret_assignments(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find assignments to variables with secret-like names."""
        # Check variable declarations
        if node.type in ["variable_declarator", "assignment_expression"]:
            # Get the variable name
            name_text = ""
            value_text = ""

            for child in node.children:
                if child.type == "identifier":
                    name_text = self._get_node_text(child, source)
                elif child.type in ["string_literal", "interpolated_string_expression"]:
                    value_text = self._get_node_text(child, source)

            if name_text and value_text:
                # Check if name matches secret pattern
                is_secret_name = any(
                    re.search(pattern, name_text)
                    for pattern in self.SECRET_NAME_PATTERNS
                )

                # Skip if value is from configuration
                if "Configuration" in value_text or "GetValue" in value_text:
                    is_secret_name = False

                # Skip interpolated strings with variables - these are not hardcoded
                # e.g., $"Data Source={dbPath}" is NOT a hardcoded secret
                if "{" in value_text and "}" in value_text:
                    is_secret_name = False

                # Skip if value contains Password= or similar BUT no actual password value
                # e.g., "Password={password}" is dynamic, not hardcoded
                clean_value = value_text.strip('"\'')
                if re.search(r"password\s*=\s*\{", clean_value, re.IGNORECASE):
                    is_secret_name = False

                if is_secret_name and len(value_text) > 5:
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=self._get_node_text(node, source),
                            context={
                                "variable_name": name_text,
                                "pattern": "secret_variable_name",
                            },
                        )
                    )

        # Check property initializers
        if node.type == "property_declaration":
            text = self._get_node_text(node, source)
            for pattern in self.SECRET_NAME_PATTERNS:
                if re.search(pattern, text):
                    # Check if has a string value
                    if '= "' in text or "= '" in text:
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=text[:100],
                                context={"pattern": "secret_property"},
                            )
                        )
                    break

        for child in node.children:
            self._find_secret_assignments(child, source, matches)

    def _find_secret_patterns(self, source: str, matches: list[RuleMatch]) -> None:
        """Find secret patterns using regex."""
        lines = source.split("\n")

        for pattern, description in self.SECRET_VALUE_PATTERNS:
            for match in re.finditer(pattern, source):
                line = source[:match.start()].count("\n") + 1

                # Skip comments
                line_content = lines[line - 1] if line <= len(lines) else ""
                if line_content.strip().startswith("//"):
                    continue

                matched_text = match.group()
                if len(matched_text) > 50:
                    matched_text = matched_text[:47] + "..."

                matches.append(
                    RuleMatch(
                        line=line,
                        column=match.start() - source.rfind("\n", 0, match.start()),
                        matched_code=matched_text,
                        context={"secret_type": description},
                    )
                )
