"""Path traversal detection rules for TypeScript/JavaScript."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class PathTraversalRule(Rule):
    """Detects potential path traversal vulnerabilities."""

    rule_id = "TS-PATH-001"
    language = "typescript"
    vulnerability_type = VulnerabilityType.PATH_TRAVERSAL
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    cwe_id = "CWE-22"
    owasp_category = "A01:2021"

    title = "Potential Path Traversal Vulnerability"
    description = (
        "The code reads or writes files using a path that may be user-controlled. "
        "An attacker could use '../' sequences to access files outside the intended directory."
    )
    remediation = (
        "1. Use path.resolve() and verify the result starts with the expected base directory\n"
        "2. Use path.normalize() and check for '..' sequences\n"
        "3. Use a whitelist of allowed filenames\n"
        "4. Never pass user input directly to file system operations"
    )

    # File system functions that take paths
    FS_FUNCTIONS = [
        "readFile", "readFileSync",
        "writeFile", "writeFileSync",
        "appendFile", "appendFileSync",
        "unlink", "unlinkSync",
        "rmdir", "rmdirSync",
        "mkdir", "mkdirSync",
        "readdir", "readdirSync",
        "stat", "statSync",
        "access", "accessSync",
        "copyFile", "copyFileSync",
        "rename", "renameSync",
        "createReadStream", "createWriteStream",
    ]

    # Express/Koa response methods that send files
    RESPONSE_FILE_METHODS = [
        "sendFile", "download", "render",
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect path traversal vulnerabilities."""
        matches: list[RuleMatch] = []
        self._find_unsafe_file_access(tree.root_node, source, matches)
        return matches

    def _find_unsafe_file_access(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find file access with potentially user-controlled paths."""
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function:
                func_text = self._get_node_text(function, source)

                # Check for fs functions
                for fs_func in self.FS_FUNCTIONS:
                    if fs_func in func_text and ("fs." in func_text or "promises." in func_text):
                        args = node.child_by_field_name("arguments")
                        if args and self._has_unsafe_path_arg(args, source):
                            matches.append(
                                RuleMatch(
                                    line=node.start_point[0] + 1,
                                    column=node.start_point[1] + 1,
                                    end_line=node.end_point[0] + 1,
                                    end_column=node.end_point[1] + 1,
                                    matched_code=self._get_node_text(node, source),
                                    context={
                                        "function": fs_func,
                                        "type": "filesystem",
                                    },
                                )
                            )
                        break

                # Check for Express sendFile/download
                for method in self.RESPONSE_FILE_METHODS:
                    if f".{method}" in func_text:
                        args = node.child_by_field_name("arguments")
                        if args and self._has_unsafe_path_arg(args, source):
                            matches.append(
                                RuleMatch(
                                    line=node.start_point[0] + 1,
                                    column=node.start_point[1] + 1,
                                    end_line=node.end_point[0] + 1,
                                    end_column=node.end_point[1] + 1,
                                    matched_code=self._get_node_text(node, source),
                                    context={
                                        "function": method,
                                        "type": "response",
                                    },
                                )
                            )
                        break

                # Check for path.join with request params
                if "path.join" in func_text or "path.resolve" in func_text:
                    args = node.child_by_field_name("arguments")
                    if args:
                        args_text = self._get_node_text(args, source)
                        # Check if any argument looks like user input
                        if any(param in args_text for param in ["req.params", "req.query", "req.body", "request."]):
                            matches.append(
                                RuleMatch(
                                    line=node.start_point[0] + 1,
                                    column=node.start_point[1] + 1,
                                    end_line=node.end_point[0] + 1,
                                    end_column=node.end_point[1] + 1,
                                    matched_code=self._get_node_text(node, source),
                                    context={
                                        "function": "path.join/resolve",
                                        "type": "path_construction",
                                    },
                                )
                            )

        for child in node.children:
            self._find_unsafe_file_access(child, source, matches)

    def _has_unsafe_path_arg(self, args_node: Node, source: str) -> bool:
        """Check if arguments contain potentially user-controlled path values."""
        args_text = self._get_node_text(args_node, source)

        # Check for request parameters
        user_input_patterns = [
            "req.params", "req.query", "req.body",
            "request.params", "request.query", "request.body",
            "ctx.params", "ctx.query", "ctx.request",
        ]

        for pattern in user_input_patterns:
            if pattern in args_text:
                return True

        # Check for template literals with substitutions (dynamic paths)
        for child in args_node.children:
            if child.type == "template_string":
                # Check if has substitutions that look like user input
                text = self._get_node_text(child, source)
                if "${" in text and any(p in text for p in ["param", "query", "body", "id", "name", "file"]):
                    return True

        return False
