"""Path traversal detection rules for C#."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from securecode.core.finding import Confidence, Severity, VulnerabilityType
from securecode.core.rule import Rule, RuleMatch, register_rule

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


@register_rule
class PathTraversalRule(Rule):
    """Detects potential path traversal vulnerabilities in C# code."""

    rule_id = "CS-PATH-001"
    language = "csharp"
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
        "1. Use Path.GetFullPath() and verify the result starts with the expected base\n"
        "2. Use Path.Combine() with validation\n"
        "3. Use a whitelist of allowed filenames\n"
        "4. Never pass user input directly to file operations\n"
        "5. Use ASP.NET Core's IFileProvider for safe file access"
    )

    # File system methods that take paths
    FILE_METHODS = [
        "ReadAllText", "ReadAllBytes", "ReadAllLines", "ReadLines",
        "WriteAllText", "WriteAllBytes", "WriteAllLines",
        "AppendAllText", "AppendAllLines",
        "Delete", "Copy", "Move",
        "OpenRead", "OpenWrite", "OpenText",
        "Create", "CreateText",
        "Exists",
    ]

    # Directory methods
    DIR_METHODS = [
        "CreateDirectory", "Delete", "Move",
        "GetFiles", "GetDirectories", "EnumerateFiles",
    ]

    # ASP.NET methods
    ASPNET_METHODS = [
        "PhysicalFile", "File", "PhysicalFileResult",
        "MapPath", "Server.MapPath",
    ]

    def detect(self, tree: Tree, source: str, file_path: str) -> list[RuleMatch]:
        """Detect path traversal vulnerabilities."""
        matches: list[RuleMatch] = []
        self._find_unsafe_file_operations(tree.root_node, source, matches)
        self._find_path_patterns(source, matches)
        return matches

    def _find_unsafe_file_operations(
        self,
        node: Node,
        source: str,
        matches: list[RuleMatch],
    ) -> None:
        """Find file operations with potentially user-controlled paths."""
        if node.type == "invocation_expression":
            text = self._get_node_text(node, source)

            # Check File.* methods
            for method in self.FILE_METHODS:
                if f"File.{method}" in text:
                    if self._has_user_controlled_path(text):
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=text[:150],
                                context={"method": f"File.{method}", "type": "file_operation"},
                            )
                        )
                    break

            # Check Directory.* methods
            for method in self.DIR_METHODS:
                if f"Directory.{method}" in text:
                    if self._has_user_controlled_path(text):
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=text[:150],
                                context={"method": f"Directory.{method}", "type": "directory_operation"},
                            )
                        )
                    break

            # Check ASP.NET file methods
            for method in self.ASPNET_METHODS:
                if method in text:
                    if self._has_user_controlled_path(text):
                        matches.append(
                            RuleMatch(
                                line=node.start_point[0] + 1,
                                column=node.start_point[1] + 1,
                                end_line=node.end_point[0] + 1,
                                end_column=node.end_point[1] + 1,
                                matched_code=text[:150],
                                context={"method": method, "type": "aspnet_file"},
                            )
                        )
                    break

            # Check Path.Combine with user input
            if "Path.Combine" in text:
                if self._has_user_controlled_path(text):
                    matches.append(
                        RuleMatch(
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                            matched_code=text[:150],
                            context={"method": "Path.Combine", "type": "path_construction"},
                        )
                    )

            # Check ZipFile extraction
            if "ExtractToDirectory" in text or "ExtractToFile" in text:
                matches.append(
                    RuleMatch(
                        line=node.start_point[0] + 1,
                        column=node.start_point[1] + 1,
                        end_line=node.end_point[0] + 1,
                        end_column=node.end_point[1] + 1,
                        matched_code=text[:150],
                        context={"method": "ZipFile.Extract*", "type": "zip_extraction"},
                    )
                )

        for child in node.children:
            self._find_unsafe_file_operations(child, source, matches)

    def _find_path_patterns(self, source: str, matches: list[RuleMatch]) -> None:
        """Find patterns that suggest path traversal vulnerabilities."""
        # Look for string concatenation with paths from request
        patterns = [
            (r'Request\[.*\]\s*\+\s*".*\\', "Path concatenation with request parameter"),
            (r'Request\..*\s*\+\s*".*\\', "Path concatenation with request value"),
        ]

        lines = source.split("\n")
        for pattern, description in patterns:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line = source[:match.start()].count("\n") + 1
                line_content = lines[line - 1] if line <= len(lines) else ""

                if line_content.strip().startswith("//"):
                    continue

                matches.append(
                    RuleMatch(
                        line=line,
                        column=match.start() - source.rfind("\n", 0, match.start()),
                        matched_code=match.group()[:100],
                        context={"description": description},
                    )
                )

    def _has_user_controlled_path(self, text: str) -> bool:
        """Check if the operation uses user-controlled paths."""
        # Only flag when there's clear user input from HTTP context
        user_input_patterns = [
            "Request[", "Request.Query", "Request.Form",
            "Request.Path", "Request.RouteValues",
            "HttpContext.Request",
            "QueryString[", "Form[",
            "RouteData.Values",
            # Controller action parameters that look like user input
            "fileName", "filePath", "uploadPath",
        ]

        text_lower = text.lower()

        # Must have a clear user input pattern
        has_user_input = any(p.lower() in text_lower for p in user_input_patterns)

        # Exclude safe patterns
        safe_patterns = [
            "AppContext.BaseDirectory",
            "Environment.GetEnvironmentVariable",
            "Configuration[", "Configuration.",
            "IWebHostEnvironment", "ContentRootPath",
            "WebRootPath", "IHostingEnvironment",
        ]
        is_safe = any(p in text for p in safe_patterns)

        return has_user_input and not is_safe
