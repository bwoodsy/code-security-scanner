"""Hardcoded secrets detection rules for TypeScript/JavaScript."""

from __future__ import annotations

import math
import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class HardcodedSecretsRule(Rule):
    """Detects hardcoded secrets, API keys, and credentials."""

    rule_id = "TS-SEC-001"
    language = "typescript"
    vulnerability_type = VulnerabilityType.HARDCODED_SECRET
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe_id = "CWE-798"
    owasp_category = "A07:2021"

    title = "Hardcoded Secret or Credential Detected"
    description = (
        "The code contains what appears to be a hardcoded secret, API key, or credential. "
        "Hardcoded secrets can be extracted from source code and used maliciously."
    )
    remediation = (
        "1. Use environment variables for secrets\n"
        "2. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)\n"
        "3. Use configuration files that are not committed to source control\n"
        "4. Rotate any secrets that may have been exposed"
    )

    # Patterns for secret variable names (must contain actual secret, not just key names)
    SECRET_NAME_PATTERNS = [
        r"(?i)^(api[_-]?key|apikey)$",  # Exact match for apiKey
        r"(?i)^(secret[_-]?key|secretkey)$",
        r"(?i)^(access[_-]?token|accesstoken)$",
        r"(?i)^(auth[_-]?token|authtoken)$",
        r"(?i)^(private[_-]?key|privatekey)$",
        r"(?i)(password|passwd|pwd)",  # Password is always suspicious
        r"(?i)^(credential)s?$",
        r"(?i)^(bearer[_-]?token)$",
        r"(?i)(jwt[_-]?secret)",
        r"(?i)^(encryption[_-]?key)$",
        r"(?i)^(signing[_-]?key)$",
        r"(?i)^(client[_-]?secret)$",
        r"(?i)^(app[_-]?secret)$",
    ]

    # Patterns that indicate a KEY NAME (not an actual secret value)
    KEY_NAME_PATTERNS = [
        r"(?i)(key|token|secret)[_-]?(name|id|identifier)$",  # e.g., tokenName, keyId
        r"(?i)^(storage|local|session|cache)[_-]?key$",  # Storage key names
        r"(?i)[_-]?key$",  # Ends with Key (like authTokenKey) - likely a key name
    ]

    # Patterns that indicate placeholder/fake values (not real secrets)
    PLACEHOLDER_PATTERNS = [
        r"(?i)^(example|sample|test|demo|fake|mock|dummy|placeholder)(_|\b)",
        r"(?i)(your|my)[_-]?(key|token|secret|password)",
        r"(?i)^(xxx+|yyy+|zzz+)$",
        r"(?i)^(changeme|change[_-]?this|replace[_-]?me|todo)$",
        r"(?i)^(insert|enter|put)[_-]?(your|here)",
        r"(?i)^[*]{3,}$",  # *** or ****
        r"(?i)^[\.\-_]{3,}$",  # ... or --- or ___
        r"(?i)^(123+|abc+|test+|asdf+)$",
        r"(?i)^.*(example\.com|localhost).*$",
    ]

    # Patterns for hash-like identifiers (not secrets, but often flagged)
    HASH_IDENTIFIER_PATTERNS = [
        # UUID format (not a secret, it's an identifier)
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        # Hash digests used as identifiers (MD5, SHA1, SHA256, etc.)
        r"^[0-9a-f]{32}$",   # MD5 (128-bit = 32 hex chars)
        r"^[0-9a-f]{40}$",   # SHA1 (160-bit = 40 hex chars)
        r"^[0-9a-f]{64}$",   # SHA256 (256-bit = 64 hex chars)
        r"^[0-9a-f]{24}$",   # MongoDB ObjectId
        # Version/build strings
        r"^\d+\.\d+\.\d+",   # Semantic versioning (1.2.3)
        r"^v\d+",            # Version tags (v1, v2, etc.)
    ]

    # Test file/path patterns to skip or lower confidence
    TEST_PATH_PATTERNS = [
        r"[/\\]__tests__[/\\]",
        r"[/\\]test[/\\]",
        r"[/\\]tests[/\\]",
        r"\.test\.(ts|js|tsx|jsx)$",
        r"\.spec\.(ts|js|tsx|jsx)$",
        r"[/\\](example|sample|mock|fixture|demo)s?[/\\]",
        r"[/\\](example|sample|mock|fixture|demo)s?\.",
    ]

    # Patterns for secret values with confidence levels
    # Format: (pattern, description, confidence_level)
    SECRET_VALUE_PATTERNS = [
        # HIGH CONFIDENCE - Known service-specific formats
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key", Confidence.HIGH),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token", Confidence.HIGH),
        (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token", Confidence.HIGH),
        (r"ghu_[a-zA-Z0-9]{36}", "GitHub User Token", Confidence.HIGH),
        (r"ghs_[a-zA-Z0-9]{36}", "GitHub Server Token", Confidence.HIGH),
        (r"ghr_[a-zA-Z0-9]{36}", "GitHub Refresh Token", Confidence.HIGH),
        (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "Slack Token", Confidence.HIGH),
        (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live API Key", Confidence.HIGH),
        (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Live Restricted Key", Confidence.HIGH),
        (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", "Private Key", Confidence.HIGH),
        (r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "JWT Token", Confidence.HIGH),

        # MEDIUM CONFIDENCE - Generic patterns requiring more context
        (r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "AWS Secret Key", Confidence.MEDIUM),
        (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test API Key", Confidence.MEDIUM),
        (r"rk_test_[0-9a-zA-Z]{24,}", "Stripe Test Restricted Key", Confidence.MEDIUM),

        # LOW CONFIDENCE - Generic patterns (need entropy check)
        (r"['\"][a-zA-Z0-9]{32,}['\"]", "Potential API Key", Confidence.LOW),
        (r"['\"][A-Za-z0-9+/]{40,}={0,2}['\"]", "Potential Base64 Encoded Secret", Confidence.LOW),
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect hardcoded secrets."""
        matches: list[RuleMatch] = []

        # Check if this is a test/example file
        is_test_file = self._is_test_file(file_path)

        # Check using AST for assignments
        self._find_secret_assignments(tree.root_node, source, matches, file_path, is_test_file)

        # Check using regex for patterns in strings
        self._find_secret_patterns(source, matches, file_path, is_test_file)

        return matches

    def _is_test_file(self, file_path: str) -> bool:
        """Check if file path indicates a test/example file."""
        return any(re.search(pattern, file_path) for pattern in self.TEST_PATH_PATTERNS)

    def _is_placeholder_value(self, value: str) -> bool:
        """Check if value looks like a placeholder/fake secret."""
        clean_value = value.strip("'\"` ")

        # Too short to be a real secret
        if len(clean_value) < 8:
            return True

        # Check placeholder patterns
        if any(re.search(pattern, clean_value) for pattern in self.PLACEHOLDER_PATTERNS):
            return True

        # Check if it's a hash-like identifier (UUID, MD5, SHA1, etc.)
        if self._looks_like_identifier_hash(clean_value):
            return True

        # Numeric only (unlikely to be a secret)
        if re.match(r"^\d+$", clean_value):
            return True

        # Too uniform (like "aaaaaaa" or "1111111")
        if len(set(clean_value)) < 3:
            return True

        return False

    def _looks_like_identifier_hash(self, value: str) -> bool:
        """
        Check if value looks like a hash or identifier (not a secret).

        These are commonly flagged as false positives:
        - UUIDs (used as resource identifiers)
        - Hash digests (MD5, SHA1, SHA256 - used as checksums/IDs)
        - MongoDB ObjectIds
        - Version strings
        """
        clean = value.strip("'\"` ")

        # Check against hash identifier patterns
        for pattern in self.HASH_IDENTIFIER_PATTERNS:
            if re.match(pattern, clean, re.IGNORECASE):
                return True

        return False

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0

        # Count frequency of each character
        entropy = 0.0
        length = len(data)

        # Calculate character frequencies
        frequencies = {}
        for char in data:
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calculate entropy
        for count in frequencies.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _has_high_entropy(self, value: str, min_entropy: float = 3.5) -> bool:
        """Check if value has high entropy (likely a real secret)."""
        clean_value = value.strip("'\"` ")

        # Need minimum length for entropy to be meaningful
        if len(clean_value) < 16:
            return False

        entropy = self._calculate_entropy(clean_value)
        return entropy >= min_entropy

    def _adjust_confidence_for_context(
        self,
        base_confidence: Confidence,
        value: str,
        is_test_file: bool,
    ) -> Confidence:
        """Adjust confidence based on context clues."""
        # Placeholder values should be low confidence
        if self._is_placeholder_value(value):
            return Confidence.LOW

        # Test files get lowered confidence
        if is_test_file and base_confidence == Confidence.HIGH:
            return Confidence.MEDIUM
        elif is_test_file and base_confidence == Confidence.MEDIUM:
            return Confidence.LOW

        # For LOW confidence patterns, check entropy
        if base_confidence == Confidence.LOW:
            if self._has_high_entropy(value):
                # Upgrade to MEDIUM if high entropy
                return Confidence.MEDIUM
            else:
                # Stay LOW or skip if very low entropy
                return Confidence.LOW

        return base_confidence

    def _find_secret_assignments(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
        file_path: str,
        is_test_file: bool,
    ) -> None:
        """Find assignments to variables with secret-like names."""
        # Check variable declarations
        if node.type in ["variable_declarator", "assignment_expression"]:
            name_node = (
                node.child_by_field_name("name")
                or node.child_by_field_name("left")
            )
            value_node = (
                node.child_by_field_name("value")
                or node.child_by_field_name("right")
            )

            if name_node and value_node:
                name_text = self._get_node_text(name_node, source)
                value_text = self._get_node_text(value_node, source)

                # Check if variable name matches secret pattern
                is_secret_name = any(
                    re.search(pattern, name_text)
                    for pattern in self.SECRET_NAME_PATTERNS
                )

                # Check if this is just a key NAME (like authTokenKey, storageKey)
                is_key_name = any(
                    re.search(pattern, name_text)
                    for pattern in self.KEY_NAME_PATTERNS
                )

                # Check if value is a string literal (not from env or config)
                is_hardcoded = value_node.type in ["string", "template_string"]

                # Skip if value is from environment
                if "process.env" in value_text or "env." in value_text.lower():
                    is_hardcoded = False

                # Skip if value looks like a simple identifier/key name (no special chars, short)
                clean_value = value_text.strip("'\"")
                if re.match(r"^[a-z_][a-z0-9_]*$", clean_value, re.IGNORECASE) and len(clean_value) < 30:
                    is_hardcoded = False  # Looks like a key name, not a secret

                # Skip placeholder values entirely
                if self._is_placeholder_value(value_text):
                    is_hardcoded = False

                if is_secret_name and is_hardcoded and not is_key_name and len(value_text) > 5:
                    # Determine confidence based on context
                    # Variable name patterns are generally MEDIUM confidence
                    base_confidence = Confidence.MEDIUM

                    # Check for high-entropy values that should be HIGH confidence
                    if self._has_high_entropy(value_text, min_entropy=4.0):
                        base_confidence = Confidence.HIGH

                    # Adjust based on context
                    final_confidence = self._adjust_confidence_for_context(
                        base_confidence, value_text, is_test_file
                    )

                    # Only add if confidence is not too low
                    skip_low_confidence = (
                        final_confidence == Confidence.LOW
                        and not self._has_high_entropy(value_text, min_entropy=3.5)
                    )

                    if not skip_low_confidence:
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
                                confidence_override=final_confidence,
                            )
                        )

        # Check object properties
        if node.type == "pair":
            key_node = node.child_by_field_name("key")
            value_node = node.child_by_field_name("value")

            if key_node and value_node:
                key_text = self._get_node_text(key_node, source)
                value_text = self._get_node_text(value_node, source)

                is_secret_name = any(
                    re.search(pattern, key_text)
                    for pattern in self.SECRET_NAME_PATTERNS
                )

                is_hardcoded = value_node.type in ["string", "template_string"]

                if "process.env" in value_text:
                    is_hardcoded = False

                # Skip placeholder values
                if self._is_placeholder_value(value_text):
                    is_hardcoded = False

                if is_secret_name and is_hardcoded and len(value_text) > 5:
                    # Determine confidence
                    base_confidence = Confidence.MEDIUM

                    # Check for high-entropy values
                    if self._has_high_entropy(value_text, min_entropy=4.0):
                        base_confidence = Confidence.HIGH

                    # Adjust based on context
                    final_confidence = self._adjust_confidence_for_context(
                        base_confidence, value_text, is_test_file
                    )

                    # Only add if confidence is not too low
                    skip_low_confidence = (
                        final_confidence == Confidence.LOW
                        and not self._has_high_entropy(value_text, min_entropy=3.5)
                    )

                    if not skip_low_confidence:
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=self._get_node_text(node, source),
                                context={
                                    "property_name": key_text,
                                    "pattern": "secret_property_name",
                                },
                                confidence_override=final_confidence,
                            )
                        )

        for child in node.children:
            self._find_secret_assignments(child, source, matches, file_path, is_test_file)

    def _find_secret_patterns(
        self,
        source: str,
        matches: list[RuleMatch],
        file_path: str,
        is_test_file: bool,
    ) -> None:
        """Find secret patterns using regex."""
        lines = source.split("\n")

        for pattern, secret_type, base_confidence in self.SECRET_VALUE_PATTERNS:
            for match in re.finditer(pattern, source):
                # Calculate line number
                line_start = source[:match.start()].count("\n") + 1

                # Skip if it looks like a comment
                line_content = lines[line_start - 1] if line_start <= len(lines) else ""
                if line_content.strip().startswith("//") or line_content.strip().startswith("*"):
                    continue

                matched_text = match.group()

                # Skip placeholder values
                if self._is_placeholder_value(matched_text):
                    continue

                # Adjust confidence based on context
                final_confidence = self._adjust_confidence_for_context(
                    base_confidence, matched_text, is_test_file
                )

                # For LOW confidence patterns with low entropy, skip them
                if final_confidence == Confidence.LOW:
                    if not self._has_high_entropy(matched_text, min_entropy=3.0):
                        continue

                # Truncate very long matches for display
                display_text = matched_text
                if len(display_text) > 50:
                    display_text = display_text[:47] + "..."

                matches.append(
                    RuleMatch(
                        line=line_start,
                        column=match.start() - source.rfind("\n", 0, match.start()),
                        matched_code=display_text,
                        context={
                            "secret_type": secret_type,
                            "pattern": "regex_match",
                        },
                        confidence_override=final_confidence,
                    )
                )
