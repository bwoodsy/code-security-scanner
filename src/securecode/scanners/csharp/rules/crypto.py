"""Weak cryptography detection rules for C#."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class WeakCryptoRule(Rule):
    """Detects usage of weak cryptographic algorithms."""

    rule_id = "CS-CRYP-001"
    language = "csharp"
    vulnerability_type = VulnerabilityType.WEAK_CRYPTO
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe_id = "CWE-327"
    owasp_category = "A02:2021"

    title = "Weak Cryptographic Algorithm Detected"
    description = (
        "The code uses a cryptographic algorithm that is considered weak or obsolete. "
        "Weak algorithms can be broken by attackers, compromising data security."
    )
    remediation = (
        "1. Use SHA-256 or SHA-512 instead of MD5 or SHA1 for hashing\n"
        "2. Use AES instead of DES or 3DES for encryption\n"
        "3. Use CBC or GCM mode instead of ECB\n"
        "4. Use RandomNumberGenerator instead of System.Random for security"
    )

    WEAK_ALGORITHMS = {
        "MD5": "MD5 is cryptographically broken",
        "SHA1": "SHA1 is deprecated for security purposes",
        "DES": "DES uses only 56-bit keys and is easily broken",
        "TripleDES": "3DES is deprecated, use AES instead",
        "RC2": "RC2 is considered weak",
        "RC4": "RC4 is broken",
    }

    WEAK_PATTERNS = [
        (r"MD5\.Create\s*\(\s*\)", "MD5 hash creation"),
        (r"SHA1\.Create\s*\(\s*\)", "SHA1 hash creation"),
        (r"new\s+MD5CryptoServiceProvider", "MD5 provider"),
        (r"new\s+SHA1CryptoServiceProvider", "SHA1 provider"),
        (r"new\s+DESCryptoServiceProvider", "DES encryption"),
        (r"new\s+TripleDESCryptoServiceProvider", "3DES encryption"),
        (r"CipherMode\.ECB", "ECB cipher mode (no IV)"),
        (r"new\s+Random\s*\(", "System.Random for security"),
        (r"PasswordDeriveBytes", "Weak PBKDF1 key derivation"),
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect weak cryptography usage."""
        matches: list[RuleMatch] = []
        self._find_weak_crypto_ast(tree.root_node, source, matches)
        self._find_weak_crypto_regex(source, matches)
        return matches

    def _find_weak_crypto_ast(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find weak crypto using AST."""
        if node.type == "invocation_expression":
            text = self._get_node_text(node, source)

            for algo, reason in self.WEAK_ALGORITHMS.items():
                if algo in text and ".Create" in text:
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=self._get_node_text(node, source),
                            context={"algorithm": algo, "reason": reason},
                        )
                    )
                    break

        if node.type == "object_creation_expression":
            text = self._get_node_text(node, source)

            for algo, reason in self.WEAK_ALGORITHMS.items():
                if algo in text:
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=self._get_node_text(node, source),
                            context={"algorithm": algo, "reason": reason},
                        )
                    )
                    break

        for child in node.children:
            self._find_weak_crypto_ast(child, source, matches)

    def _find_weak_crypto_regex(self, source: str, matches: list[RuleMatch]) -> None:
        """Find weak crypto using regex patterns."""
        for pattern, description in self.WEAK_PATTERNS:
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
