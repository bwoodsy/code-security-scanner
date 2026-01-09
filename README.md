# SecureCode-AI

[![CI](https://github.com/user/securecode-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/user/securecode-ai/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

> A production-ready static code security scanner for TypeScript and C# codebases

SecureCode-AI analyzes your source code to detect security vulnerabilities before they reach production. Built with an extensible plugin architecture, it supports multiple languages and can be easily extended with custom rules.

## Features

- **Multi-Language Support**: TypeScript, JavaScript, TSX, JSX, and C#
- **Comprehensive Detection**: XSS, SQL Injection, Command Injection, Path Traversal, Hardcoded Secrets, Weak Cryptography, Insecure Deserialization
- **Beautiful Reports**: JSON and HTML reports with executive dashboards
- **CI/CD Ready**: Docker support and GitHub Actions integration
- **Extensible**: Plugin-based architecture for adding new languages and rules
- **Fast**: Parallel scanning with tree-sitter AST parsing

## Supported Vulnerabilities

| Vulnerability Type | TypeScript/JS | C# |
|-------------------|---------------|-----|
| Cross-Site Scripting (XSS) | ✅ | ✅ |
| SQL Injection | ✅ | ✅ |
| Command Injection | ✅ | ✅ |
| Path Traversal | ✅ | ✅ |
| Hardcoded Secrets | ✅ | ✅ |
| Weak Cryptography | - | ✅ |
| Insecure Deserialization | - | ✅ |
| SSRF | ✅ | - |
| Prototype Pollution | ✅ | - |

## Installation

### Using pip

```bash
pip install securecode-ai
```

### Using Poetry (Development)

```bash
# Clone the repository
git clone https://github.com/user/securecode-ai.git
cd securecode-ai

# Install with Poetry
poetry install

# Or install with pip in editable mode
pip install -e ".[dev]"
```

### Using Docker

```bash
# Build the image
docker build -t securecode-ai .

# Or pull from registry (when available)
docker pull securecode-ai:latest
```

## Quick Start

### Basic Scan

```bash
# Scan a directory
securecode scan ./src

# Scan with specific output format
securecode scan ./src --output json
securecode scan ./src --output html
securecode scan ./src --output both

# Filter by severity
securecode scan ./src --severity critical,high

# Scan specific languages only
securecode scan ./src --languages typescript,csharp

# Quick single-file check
securecode check ./src/api/handler.ts
```

### Docker Usage

```bash
# Scan local code
docker run -v /path/to/code:/code:ro -v ./results:/results \
  securecode-ai scan /code --output both

# Using docker-compose
docker-compose run securecode scan /code --severity high,critical
```

## Configuration

Create a `.securecode.yml` file in your project root:

```yaml
# Directories to exclude from scanning
exclude_dirs:
  - node_modules
  - bin
  - obj
  - dist
  - .git
  - __pycache__
  - coverage

# Minimum severity to report (critical, high, medium, low, info)
severity_threshold: medium

# Output formats to generate
output_formats:
  - json
  - html

# Output directory for reports
output_dir: ./securecode-results

# Maximum file size to scan (skip larger files)
max_file_size: 10MB

# Number of parallel workers
parallel_workers: 4
```

## CLI Reference

```
Usage: securecode [OPTIONS] COMMAND [ARGS]...

  SecureCode-AI - Static security scanner for TypeScript and C#

Options:
  --version  Show version and exit
  --help     Show this message and exit

Commands:
  scan   Scan a directory for security vulnerabilities
  check  Quick security check for a single file
```

### scan command

```
Usage: securecode scan [OPTIONS] PATH

  Scan a directory for security vulnerabilities.

Arguments:
  PATH  Directory to scan  [required]

Options:
  -o, --output [json|html|both]   Output format (default: both)
  -s, --severity TEXT             Severity filter (comma-separated)
  -l, --languages TEXT            Languages to scan (comma-separated)
  -e, --exclude TEXT              Directories to exclude
  --output-dir PATH               Output directory for reports
  --help                          Show this message and exit
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no vulnerabilities found |
| 1 | Scan completed, vulnerabilities found |
| 2 | Error occurred (invalid path, configuration error, etc.) |

## Output Examples

### Console Output

```
SecureCode-AI v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scanning: /path/to/project
Files:    150 (.ts: 120, .cs: 30)

[████████████████████████████████████████] 150/150

SCAN COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Summary:
  CRITICAL:  2
  HIGH:      8
  MEDIUM:   10
  LOW:       5
  ─────────────
  TOTAL:    25

Top Vulnerable Files:
  1. src/api/handler.ts       (5 issues)
  2. Controllers/Auth.cs      (4 issues)
  3. src/utils/db.ts          (3 issues)

Reports saved to:
  → ./securecode-results/securecode-report-2025-01-06T120000.json
  → ./securecode-results/securecode-report-2025-01-06T120000.html
```

### JSON Report Structure

```json
{
  "schema_version": "1.0",
  "scan_metadata": {
    "scan_id": "scan-abc123",
    "timestamp": "2025-01-06T12:00:00Z",
    "scanner_version": "1.0.0",
    "target_directory": "/path/to/project",
    "files_scanned": 150,
    "scan_duration_seconds": 2.5
  },
  "summary": {
    "total_vulnerabilities": 25,
    "by_severity": {
      "CRITICAL": 2,
      "HIGH": 8,
      "MEDIUM": 10,
      "LOW": 5
    },
    "by_type": {
      "XSS": 5,
      "SQL_INJECTION": 3,
      "HARDCODED_SECRET": 10
    }
  },
  "vulnerabilities": [
    {
      "id": "vuln-001",
      "rule_id": "TS-XSS-001",
      "file_path": "src/components/Display.tsx",
      "line": 42,
      "column": 10,
      "vulnerability_type": "XSS",
      "severity": "HIGH",
      "confidence": "HIGH",
      "title": "Potential XSS via innerHTML",
      "description": "Using innerHTML with dynamic content can lead to XSS attacks",
      "remediation": "Use textContent for plain text or sanitize HTML input"
    }
  ]
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (Typer)                          │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    ScanOrchestrator                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │File Discovery│  │   Parallel  │  │ Result Aggregation │  │
│  └─────────────┘  │   Scanner   │  └─────────────────────┘  │
│                   └─────────────┘                            │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────┐
│TypeScript Scanner│ │ C# Scanner │ │Future: Python│
│  ┌───────────┐  │ │ ┌─────────┐ │ │   Scanner   │
│  │tree-sitter│  │ │ │tree-sitter│ │ └─────────────┘
│  │  parser   │  │ │ │ parser  │ │
│  └───────────┘  │ │ └─────────┘ │
│  ┌───────────┐  │ │ ┌─────────┐ │
│  │   Rules   │  │ │ │  Rules  │ │
│  │  Registry │  │ │ │ Registry│ │
│  └───────────┘  │ │ └─────────┘ │
└─────────────────┘ └─────────────┘
          │               │
          └───────┬───────┘
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    Report Generator                          │
│         ┌──────────────┐  ┌──────────────┐                  │
│         │ JSON Reporter │  │ HTML Reporter │                 │
│         └──────────────┘  └──────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

## Extending SecureCode-AI

### Adding a New Language Scanner

```python
# src/securecode/scanners/python/scanner.py
from securecode.core.scanner import BaseScanner

class PythonScanner(BaseScanner):
    """Scanner for Python source files."""

    @property
    def language_id(self) -> str:
        return "python"

    @property
    def file_extensions(self) -> list[str]:
        return [".py"]

    def scan_file(self, file_path, content, base_path):
        # Implementation
        pass
```

### Adding a New Rule

```python
# src/securecode/scanners/python/rules/injection.py
from securecode.core.rule import Rule, RuleMatch, register_rule

@register_rule
class PythonSQLInjection(Rule):
    """Detect SQL injection in Python code."""

    rule_id = "PY-SQL-001"
    language = "python"
    vulnerability_type = VulnerabilityType.SQL_INJECTION
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    title = "SQL Injection via String Formatting"
    description = "SQL query built with f-string or .format() is vulnerable"
    remediation = "Use parameterized queries with placeholders"
    cwe_id = "CWE-89"
    owasp_category = "A03:2021"

    def detect(self, tree, source, file_path):
        matches = []
        # Detection logic using tree-sitter AST
        return matches
```

## Development

### Setup

```bash
# Clone and install
git clone https://github.com/user/securecode-ai.git
cd securecode-ai
poetry install

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=securecode --cov-report=html

# Run specific test file
pytest tests/unit/test_typescript_scanner.py

# Run tests in Docker
docker-compose --profile test run securecode-test
```

### Code Quality

```bash
# Lint with Ruff
ruff check src/ tests/

# Format with Ruff
ruff format src/ tests/

# Type check with MyPy
mypy src/
```

## Roadmap

### Phase 1: Foundation (Current)
- [x] TypeScript/JavaScript scanner
- [x] C# scanner
- [x] JSON/HTML reports
- [x] CLI interface
- [x] Docker support

### Phase 2: Language Expansion
- [ ] Python support (Django, Flask, FastAPI patterns)
- [ ] Java support (Spring, Jakarta EE patterns)
- [ ] Go support (Gin, Echo patterns)
- [ ] PHP support (Laravel, Symfony patterns)

### Phase 3: Advanced Features
- [ ] SARIF output format (for IDE integration)
- [ ] VS Code extension
- [ ] GitHub Action marketplace release
- [ ] GitLab CI integration
- [ ] Incremental scanning (only changed files)

### Phase 4: Security Test Generation
- [ ] Generate pytest/unittest tests from scan results
- [ ] Create test cases that verify vulnerability fixes
- [ ] Output security regression test suites
- [ ] Integration with existing test frameworks

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-scanner`)
3. Make your changes
4. Run tests (`pytest`)
5. Run linting (`ruff check .`)
6. Commit your changes (`git commit -m 'Add Python scanner'`)
7. Push to the branch (`git push origin feature/new-scanner`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [tree-sitter](https://tree-sitter.github.io/tree-sitter/) - Fast incremental parsing
- [Typer](https://typer.tiangolo.com/) - CLI framework
- [Rich](https://rich.readthedocs.io/) - Terminal formatting
- [Pydantic](https://docs.pydantic.dev/) - Data validation
