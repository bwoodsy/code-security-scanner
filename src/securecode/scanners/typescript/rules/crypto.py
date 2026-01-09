"""Cryptographic weakness detection rules for TypeScript/JavaScript."""

from __future__ import annotations

from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class InsecureRandomnessRule(Rule):
    """Detects use of insecure random number generation."""

    rule_id = "TS-RAND-001"
    language = "typescript"
    vulnerability_type = VulnerabilityType.WEAK_CRYPTO
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    cwe_id = "CWE-330"
    owasp_category = "A02:2021"

    title = "Insecure Random Number Generation"
    description = (
        "Math.random() is not cryptographically secure and should not be used for "
        "security-sensitive operations like generating tokens, passwords, or session IDs."
    )
    remediation = (
        "1. Use crypto.randomBytes() or crypto.randomUUID() in Node.js\n"
        "2. Use crypto.getRandomValues() in browsers\n"
        "3. Use a library like 'uuid' for generating UUIDs\n"
        "4. Never use Math.random() for tokens, passwords, or security keys"
    )

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect insecure randomness usage."""
        matches: list[RuleMatch] = []
        self._find_math_random(tree.root_node, source, matches, file_path)
        return matches

    def _find_math_random(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
        file_path: str,
    ) -> None:
        """Find Math.random() usage in security-sensitive contexts."""
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)

                if func_text == "Math.random":
                    # Check context - look at parent/grandparent for variable name
                    context_node = node.parent
                    context_text = ""
                    if context_node:
                        context_text = self._get_node_text(context_node, source).lower()

                    # Check if used in security context
                    security_keywords = [
                        "token", "secret", "key", "password", "passwd",
                        "session", "auth", "csrf", "nonce", "salt",
                        "id", "uuid", "guid", "random",
                    ]

                    is_security_context = any(kw in context_text for kw in security_keywords)

                    # Also flag if in auth-related files
                    is_security_file = any(
                        kw in file_path.lower()
                        for kw in ["auth", "security", "token", "session", "crypto"]
                    )

                    if is_security_context or is_security_file:
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(
                                    context_node if context_node else node, source
                                )[:100],
                                context={
                                    "function": "Math.random",
                                    "security_context": is_security_context,
                                },
                            )
                        )

        for child in node.children:
            self._find_math_random(child, source, matches, file_path)


@register_rule
class WeakHashingRule(Rule):
    """Detects use of weak hashing algorithms."""

    rule_id = "TS-HASH-001"
    language = "typescript"
    vulnerability_type = VulnerabilityType.WEAK_CRYPTO
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe_id = "CWE-328"
    owasp_category = "A02:2021"

    title = "Use of Weak Hashing Algorithm"
    description = (
        "MD5 and SHA1 are cryptographically weak and should not be used for "
        "password hashing or security-sensitive operations."
    )
    remediation = (
        "1. Use bcrypt, scrypt, or Argon2 for password hashing\n"
        "2. Use SHA-256 or SHA-3 for general hashing\n"
        "3. Never use MD5 or SHA1 for security purposes"
    )

    WEAK_ALGORITHMS = ["md5", "sha1", "sha-1"]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect weak hashing algorithm usage."""
        matches: list[RuleMatch] = []
        self._find_weak_hash(tree.root_node, source, matches)
        return matches

    def _find_weak_hash(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find weak hashing algorithm usage."""
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)

                # Check for crypto.createHash('md5')
                if "createHash" in func_text:
                    args = node.child_by_field_name("arguments")
                    if args:
                        args_text = self._get_node_text(args, source).lower()
                        for weak_algo in self.WEAK_ALGORITHMS:
                            if weak_algo in args_text:
                                matches.append(
                                    RuleMatch(
                                        line=node.start_point[0] + 1,
                                        column=node.start_point[1] + 1,
                                        end_line=node.end_point[0] + 1,
                                        end_column=node.end_point[1] + 1,
                                        matched_code=self._get_node_text(node, source),
                                        context={
                                            "algorithm": weak_algo,
                                            "function": "createHash",
                                        },
                                    )
                                )
                                break

        # Also check for string literals containing weak algorithm names in crypto contexts
        if node.type == "string" or node.type == "template_string":
            text = self._get_node_text(node, source).lower()
            parent_text = self._get_node_text(node.parent, source) if node.parent else ""

            if "crypto" in parent_text.lower() or "hash" in parent_text.lower():
                for weak_algo in self.WEAK_ALGORITHMS:
                    if weak_algo in text:
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(node.parent if node.parent else node, source),
                                context={"algorithm": weak_algo},
                            )
                        )
                        break

        for child in node.children:
            self._find_weak_hash(child, source, matches)
