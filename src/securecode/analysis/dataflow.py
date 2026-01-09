"""Data flow analyzer for reducing false positives."""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING

from securecode.analysis.models import AnalysisVerdict, DataFlowResult, DeepAnalysisStats
from securecode.analysis.sources_sinks import (
    get_sanitizers,
    get_sources,
    is_known_source,
    is_safe_value,
)
from securecode.core.finding import Confidence, Vulnerability

if TYPE_CHECKING:
    from securecode.config import ScanConfig

logger = logging.getLogger(__name__)


class DataFlowAnalyzer:
    """Analyzes data flow to reduce false positives in vulnerability detection."""

    def __init__(self, config: "ScanConfig | None" = None) -> None:
        """Initialize the analyzer."""
        self.config = config
        self.max_trace_depth = 20 if config is None else getattr(config, "deep_analysis_trace_depth", 20)
        self.stats = DeepAnalysisStats()

    def analyze(
        self,
        vulnerabilities: list[Vulnerability],
        source_map: dict[Path, str],
    ) -> tuple[list[Vulnerability], DeepAnalysisStats]:
        """
        Analyze vulnerabilities and filter/adjust based on data flow.

        Args:
            vulnerabilities: List of detected vulnerabilities
            source_map: Map of file paths to source code content

        Returns:
            Tuple of (filtered vulnerabilities, analysis statistics)
        """
        start_time = time.time()
        self.stats = DeepAnalysisStats()
        analyzed_vulns: list[Vulnerability] = []

        for vuln in vulnerabilities:
            self.stats.total_analyzed += 1

            # Get source code for this file
            source_code = source_map.get(vuln.file_path, "")
            if not source_code:
                # Can't analyze without source - keep as-is
                analyzed_vulns.append(vuln)
                continue

            # Perform data flow analysis
            result = self._analyze_vulnerability(vuln, source_code)

            # Update statistics
            self._update_stats(result)

            # Decide whether to keep, adjust, or filter
            if result.verdict == AnalysisVerdict.SAFE:
                self.stats.safe_filtered += 1
                logger.debug(
                    f"Filtered {vuln.id} as SAFE: {result.analysis_notes}"
                )
                continue  # Filter out safe findings

            # Adjust confidence based on analysis
            adjusted_vuln = self._adjust_vulnerability(vuln, result)
            analyzed_vulns.append(adjusted_vuln)

        self.stats.analysis_time_seconds = time.time() - start_time
        logger.info(
            f"Deep analysis complete: {self.stats.total_analyzed} analyzed, "
            f"{self.stats.safe_filtered} filtered, "
            f"{len(analyzed_vulns)} remaining"
        )

        return analyzed_vulns, self.stats

    def _analyze_vulnerability(
        self,
        vuln: Vulnerability,
        source_code: str,
    ) -> DataFlowResult:
        """Analyze a single vulnerability for data flow."""
        result = DataFlowResult(performed=True)

        try:
            # Special handling for HARDCODED_SECRET - don't do taint analysis
            # Secrets are about finding constant values in code, not tracing user input
            if vuln.vulnerability_type.value == "HARDCODED_SECRET":
                result.analysis_notes = "Hardcoded secret - constant value analysis, not taint flow"
                result.verdict = AnalysisVerdict.CONFIRMED  # Secrets are confirmed by pattern match
                result.source_found = True
                result.source_type = "constant/literal"
                result.confidence_adjustment = 0.0  # No adjustment needed
                return result

            # Extract variable from the matched code
            sink_var = self._extract_sink_variable(vuln.matched_code, vuln.vulnerability_type.value)
            result.sink_variable = sink_var

            if not sink_var:
                result.analysis_notes = "Could not extract variable from sink"
                result.verdict = AnalysisVerdict.POSSIBLE
                return result

            # Split source into lines
            lines = source_code.split("\n")

            # Trace backward from sink to find source
            trace_result = self._trace_backward(
                lines=lines,
                start_line=vuln.line,
                variable=sink_var,
                language=vuln.language,
            )
            result.source_found = trace_result["source_found"]
            result.source_type = trace_result.get("source_type")
            result.source_line = trace_result.get("source_line")
            result.trace_path = trace_result.get("trace_path", [])
            result.trace_depth = len(result.trace_path)

            # Check for sanitization between source and sink
            if result.source_found and result.source_line:
                sanitizer_result = self._check_sanitization(
                    lines=lines,
                    start_line=result.source_line,
                    end_line=vuln.line,
                    language=vuln.language,
                    vuln_type=vuln.vulnerability_type.value,
                )
                result.sanitization_found = sanitizer_result["found"]
                result.sanitizer_type = sanitizer_result.get("sanitizer")
                result.sanitizer_line = sanitizer_result.get("line")

            # Determine verdict
            result.verdict = self._determine_verdict(result, trace_result)
            result.confidence_adjustment = self._calculate_confidence_adjustment(result)
            result.analysis_notes = self._generate_notes(result)
            result.recommendation = self._generate_recommendation(result, vuln.vulnerability_type.value)

        except Exception as e:
            logger.debug(f"Error analyzing {vuln.id}: {e}")
            result.analysis_notes = f"Analysis error: {str(e)}"
            result.verdict = AnalysisVerdict.POSSIBLE

        return result

    def _extract_sink_variable(self, matched_code: str, vuln_type: str) -> str | None:
        """Extract the variable name being used in the sink."""
        if not matched_code:
            return None

        # Different extraction strategies based on vulnerability type
        patterns = [
            # Assignment: innerHTML = variable
            r"(?:innerHTML|outerHTML)\s*=\s*(\w+)",
            # Template literal substitution: ${variable}
            r"\$\{(\w+)\}",
            # Function argument: func(variable)
            r"\(\s*(\w+)\s*\)",
            # Function with template: query(`...${variable}...`)
            r"`[^`]*\$\{(\w+)\}",
            # Property access: obj.method(variable)
            r"\.\w+\(\s*(\w+)",
            # Concatenation: "string" + variable
            r'"\s*\+\s*(\w+)',
            r"'\s*\+\s*(\w+)",
            # Variable alone
            r"(\w+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, matched_code)
            if match:
                var_name = match.group(1)
                # Skip common non-variable matches
                if var_name.lower() not in ("true", "false", "null", "undefined", "this", "new"):
                    return var_name

        return None

    def _trace_backward(
        self,
        lines: list[str],
        start_line: int,
        variable: str,
        language: str,
        depth: int = 0,
    ) -> dict:
        """Trace a variable backward to find its source."""
        if depth > self.max_trace_depth:
            return {
                "source_found": False,
                "trace_path": [f"Max trace depth ({self.max_trace_depth}) reached"],
            }

        trace_path: list[str] = []
        current_var = variable

        # Go backward from start_line
        for line_num in range(start_line - 1, max(0, start_line - 100), -1):
            if line_num >= len(lines):
                continue

            line = lines[line_num]
            line_stripped = line.strip()

            # Skip empty lines and comments
            if not line_stripped or line_stripped.startswith("//") or line_stripped.startswith("*"):
                continue

            # Check if this line is a known source
            is_source, source_type = is_known_source(line, language)
            if is_source and current_var in line:
                trace_path.append(f"Line {line_num + 1}: Found source '{source_type}'")
                return {
                    "source_found": True,
                    "source_type": source_type,
                    "source_line": line_num + 1,
                    "trace_path": trace_path,
                }

            # Check for assignment to current variable
            assignment_patterns = [
                # const/let/var x = ...
                rf"(?:const|let|var)\s+{re.escape(current_var)}\s*=\s*(.+)",
                # x = ...
                rf"^{re.escape(current_var)}\s*=\s*(.+)",
                # Destructuring: const { x } = ...
                rf"(?:const|let|var)\s*\{{\s*[^}}]*{re.escape(current_var)}[^}}]*\}}\s*=\s*(.+)",
                # Destructuring with rename: const { y: x } = ...
                rf"(?:const|let|var)\s*\{{\s*\w+\s*:\s*{re.escape(current_var)}\s*\}}\s*=\s*(.+)",
            ]

            for pattern in assignment_patterns:
                match = re.search(pattern, line)
                if match:
                    rhs = match.group(1).strip().rstrip(";")
                    trace_path.append(f"Line {line_num + 1}: {current_var} = {rhs[:50]}...")

                    # Check if RHS is a literal (safe)
                    if is_safe_value(rhs):
                        return {
                            "source_found": False,
                            "analysis_notes": "Value is a constant/literal",
                            "trace_path": trace_path,
                        }

                    # Check if RHS is a known source
                    is_source, source_type = is_known_source(rhs, language)
                    if is_source:
                        return {
                            "source_found": True,
                            "source_type": source_type,
                            "source_line": line_num + 1,
                            "trace_path": trace_path,
                        }

                    # Extract new variable to trace
                    new_var = self._extract_variable_from_expression(rhs)
                    if new_var and new_var != current_var:
                        current_var = new_var
                    break

            # Check for function parameter
            func_param_pattern = rf"(?:function|async\s+function)?\s*\w*\s*\(\s*[^)]*\b{re.escape(current_var)}\b"
            if re.search(func_param_pattern, line):
                trace_path.append(f"Line {line_num + 1}: {current_var} is a function parameter")
                return {
                    "source_found": True,
                    "source_type": "function_parameter",
                    "source_line": line_num + 1,
                    "trace_path": trace_path,
                    "needs_caller_analysis": True,
                }

        return {
            "source_found": False,
            "analysis_notes": "Source not found within trace depth",
            "trace_path": trace_path,
        }

    def _extract_variable_from_expression(self, expression: str) -> str | None:
        """Extract a variable name from an expression."""
        # Remove common wrappers
        expression = expression.strip()

        # Direct variable
        match = re.match(r"^(\w+)(?:\s*;)?$", expression)
        if match:
            return match.group(1)

        # Property access: obj.prop or obj.method()
        match = re.match(r"^(\w+)\.", expression)
        if match:
            return match.group(1)

        # Function call: func(arg) - return first arg
        match = re.search(r"\(\s*(\w+)", expression)
        if match:
            return match.group(1)

        # Await expression
        match = re.match(r"^await\s+(\w+)", expression)
        if match:
            return match.group(1)

        return None

    def _check_sanitization(
        self,
        lines: list[str],
        start_line: int,
        end_line: int,
        language: str,
        vuln_type: str,
    ) -> dict:
        """Check if there's sanitization between source and sink."""
        sanitizers = get_sanitizers(language)

        # Check lines between source and sink
        for line_num in range(start_line - 1, min(end_line, len(lines))):
            line = lines[line_num]

            for sanitizer_pattern in sanitizers:
                if re.search(sanitizer_pattern, line, re.IGNORECASE):
                    return {
                        "found": True,
                        "sanitizer": sanitizer_pattern.replace("\\", ""),
                        "line": line_num + 1,
                    }

        # Check for vuln-type specific sanitization
        type_specific = self._check_type_specific_sanitization(lines, start_line, end_line, vuln_type)
        if type_specific["found"]:
            return type_specific

        return {"found": False}

    def _check_type_specific_sanitization(
        self,
        lines: list[str],
        start_line: int,
        end_line: int,
        vuln_type: str,
    ) -> dict:
        """Check for vulnerability-type specific sanitization patterns."""
        code_block = "\n".join(lines[start_line - 1:end_line])

        if vuln_type == "SQL_INJECTION":
            # Check for parameterized queries
            if re.search(r"\?\s*,|\$\d+|:\w+|@\w+", code_block):
                return {"found": True, "sanitizer": "Parameterized query", "line": start_line}

        elif vuln_type == "XSS":
            # Check for JSX (auto-escaped)
            if re.search(r"<\w+[^>]*>.*\{.*\}.*</\w+>", code_block):
                return {"found": True, "sanitizer": "JSX auto-escaping", "line": start_line}

        elif vuln_type == "PATH_TRAVERSAL":
            # Check for path.basename or path.normalize
            if re.search(r"path\.(basename|normalize|resolve)", code_block, re.IGNORECASE):
                return {"found": True, "sanitizer": "Path normalization", "line": start_line}

        elif vuln_type == "COMMAND_INJECTION":
            # Check for spawn with array args (not shell)
            if re.search(r"spawn\s*\(\s*\w+\s*,\s*\[", code_block):
                if "shell" not in code_block.lower() or "shell: false" in code_block.lower():
                    return {"found": True, "sanitizer": "spawn with array args", "line": start_line}

        return {"found": False}

    def _determine_verdict(self, result: DataFlowResult, trace_result: dict) -> AnalysisVerdict:
        """Determine the verdict based on analysis results."""
        if result.sanitization_found:
            return AnalysisVerdict.SAFE

        if not result.source_found:
            # Source not found - could be safe or just out of scope
            if trace_result.get("analysis_notes") == "Value is a constant/literal":
                return AnalysisVerdict.SAFE
            return AnalysisVerdict.UNLIKELY

        # Source found, check what kind
        source_type = result.source_type or ""

        if source_type == "function_parameter":
            # Need caller analysis - mark as possible
            return AnalysisVerdict.POSSIBLE

        if any(src in source_type.lower() for src in ["req.", "request.", "ctx.", "event."]):
            # Definitely user input
            return AnalysisVerdict.CONFIRMED

        if any(src in source_type.lower() for src in ["params", "query", "body", "form"]):
            return AnalysisVerdict.LIKELY

        return AnalysisVerdict.POSSIBLE

    def _calculate_confidence_adjustment(self, result: DataFlowResult) -> float:
        """Calculate confidence adjustment based on analysis."""
        adjustment = 0.0

        if result.verdict == AnalysisVerdict.SAFE:
            adjustment = -0.5  # Strong decrease
        elif result.verdict == AnalysisVerdict.UNLIKELY:
            adjustment = -0.3
        elif result.verdict == AnalysisVerdict.POSSIBLE:
            adjustment = -0.1
        elif result.verdict == AnalysisVerdict.LIKELY:
            adjustment = 0.0  # No change
        elif result.verdict == AnalysisVerdict.CONFIRMED:
            adjustment = 0.1  # Slight increase

        if result.sanitization_found:
            adjustment -= 0.2

        return max(-0.5, min(0.2, adjustment))

    def _generate_notes(self, result: DataFlowResult) -> str:
        """Generate human-readable analysis notes."""
        notes = []

        if result.source_found:
            notes.append(f"Source identified: {result.source_type}")
            if result.source_line:
                notes.append(f"Source at line {result.source_line}")
        else:
            notes.append("User input source not found in trace")

        if result.sanitization_found:
            notes.append(f"Sanitization detected: {result.sanitizer_type}")
            if result.sanitizer_line:
                notes.append(f"Sanitizer at line {result.sanitizer_line}")

        notes.append(f"Verdict: {result.verdict.value}")

        return "; ".join(notes)

    def _generate_recommendation(self, result: DataFlowResult, vuln_type: str) -> str:
        """Generate recommendation based on analysis."""
        if result.verdict == AnalysisVerdict.SAFE:
            return "Low risk - data appears sanitized or from safe source"

        if result.verdict == AnalysisVerdict.UNLIKELY:
            return "Low risk - source not traced to user input"

        if result.verdict == AnalysisVerdict.CONFIRMED:
            return f"High risk - user input flows directly to {vuln_type} sink without sanitization"

        if result.verdict == AnalysisVerdict.LIKELY:
            return "Medium risk - likely user input, verify sanitization"

        return "Manual review recommended - data flow unclear"

    def _adjust_vulnerability(
        self,
        vuln: Vulnerability,
        result: DataFlowResult,
    ) -> Vulnerability:
        """Create adjusted vulnerability with deep analysis results."""
        # Adjust confidence based on analysis
        new_confidence = vuln.confidence
        if result.confidence_adjustment < -0.2:
            if vuln.confidence == Confidence.HIGH:
                new_confidence = Confidence.MEDIUM
            elif vuln.confidence == Confidence.MEDIUM:
                new_confidence = Confidence.LOW
        elif result.confidence_adjustment > 0.1:
            if vuln.confidence == Confidence.LOW:
                new_confidence = Confidence.MEDIUM
            elif vuln.confidence == Confidence.MEDIUM:
                new_confidence = Confidence.HIGH

        # Create new vulnerability with updated metadata
        updated_metadata = dict(vuln.metadata) if vuln.metadata else {}
        updated_metadata["deep_analysis"] = result.to_dict()

        return Vulnerability(
            id=vuln.id,
            rule_id=vuln.rule_id,
            file_path=vuln.file_path,
            relative_path=vuln.relative_path,
            line=vuln.line,
            column=vuln.column,
            end_line=vuln.end_line,
            end_column=vuln.end_column,
            code_snippet=vuln.code_snippet,
            matched_code=vuln.matched_code,
            vulnerability_type=vuln.vulnerability_type,
            severity=vuln.severity,
            confidence=new_confidence,
            title=vuln.title,
            description=vuln.description,
            remediation=vuln.remediation,
            cwe_id=vuln.cwe_id,
            owasp_category=vuln.owasp_category,
            language=vuln.language,
            metadata=updated_metadata,
        )

    def _update_stats(self, result: DataFlowResult) -> None:
        """Update statistics based on analysis result."""
        verdict = result.verdict.value
        self.stats.verdicts[verdict] = self.stats.verdicts.get(verdict, 0) + 1

        if result.verdict == AnalysisVerdict.CONFIRMED:
            self.stats.confirmed_vulnerabilities += 1
        elif result.verdict == AnalysisVerdict.LIKELY:
            self.stats.likely_vulnerabilities += 1
        elif result.verdict == AnalysisVerdict.POSSIBLE:
            self.stats.possible_vulnerabilities += 1
        elif result.verdict == AnalysisVerdict.UNLIKELY:
            self.stats.unlikely_vulnerabilities += 1
