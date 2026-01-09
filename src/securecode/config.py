"""Configuration management for SecureCode-AI."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from securecode.core.finding import Severity

logger = logging.getLogger(__name__)


class ScanConfig(BaseModel):
    """Configuration for a single scan operation."""

    # Directories and files
    exclude_dirs: list[str] = Field(
        default_factory=lambda: [
            "node_modules",
            "bin",
            "obj",
            "dist",
            "build",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            "coverage",
            ".nyc_output",
        ],
        description="Directories to exclude from scanning",
    )
    exclude_patterns: list[str] = Field(
        default_factory=list,
        description="Glob patterns for files/directories to exclude",
    )

    # Filtering
    severity_threshold: Severity = Field(
        default=Severity.LOW,
        description="Minimum severity level to report",
    )
    languages: list[str] = Field(
        default_factory=list,
        description="Languages to scan (empty = all supported)",
    )

    # Output
    output_formats: list[str] = Field(
        default_factory=lambda: ["json", "html"],
        description="Report formats to generate",
    )
    output_dir: Path = Field(
        default=Path("./securecode-results"),
        description="Directory for output reports",
    )

    # Performance
    max_file_size_mb: float = Field(
        default=10.0,
        description="Skip files larger than this size (MB)",
    )
    parallel_workers: int = Field(
        default=4,
        ge=1,
        le=32,
        description="Number of parallel workers for scanning",
    )

    # Behavior
    fail_on_findings: bool = Field(
        default=True,
        description="Exit with code 1 if vulnerabilities found",
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose output",
    )

    # Deep Analysis
    enable_deep_analysis: bool = Field(
        default=True,
        description="Enable data flow analysis to reduce false positives",
    )
    deep_analysis_trace_depth: int = Field(
        default=20,
        ge=5,
        le=100,
        description="Max lines to trace backward for data flow analysis",
    )
    deep_analysis_filter_safe: bool = Field(
        default=True,
        description="Filter out findings marked as SAFE by deep analysis",
    )

    class Config:
        """Pydantic configuration."""

        validate_assignment = True


class AppSettings(BaseSettings):
    """Application-level settings from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="SECURECODE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: Path | None = Field(default=None, description="Log file path")

    # Output
    output_dir: Path = Field(
        default=Path("./securecode-results"),
        description="Default output directory",
    )
    no_color: bool = Field(default=False, description="Disable colored output")

    # Performance
    parallel_workers: int = Field(default=4, description="Default parallel workers")


def load_config_file(config_path: Path | None = None) -> ScanConfig:
    """Load configuration from a YAML file.

    Args:
        config_path: Path to config file. If None, searches for .securecode.yml
                     in the current directory and parent directories.

    Returns:
        ScanConfig object with loaded settings
    """
    if config_path is None:
        config_path = find_config_file()

    if config_path is None or not config_path.exists():
        logger.debug("No config file found, using defaults")
        return ScanConfig()

    try:
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        logger.info(f"Loaded configuration from {config_path}")
        return ScanConfig(**data)
    except Exception as e:
        logger.warning(f"Error loading config file {config_path}: {e}")
        return ScanConfig()


def find_config_file(start_dir: Path | None = None) -> Path | None:
    """Find the nearest .securecode.yml config file.

    Searches in the start directory and parent directories.

    Args:
        start_dir: Directory to start searching from (defaults to cwd)

    Returns:
        Path to config file or None if not found
    """
    if start_dir is None:
        start_dir = Path.cwd()

    config_names = [".securecode.yml", ".securecode.yaml", "securecode.yml", "securecode.yaml"]

    current = start_dir.resolve()
    while True:
        for name in config_names:
            config_path = current / name
            if config_path.exists():
                return config_path

        parent = current.parent
        if parent == current:
            # Reached root
            break
        current = parent

    return None


def merge_configs(
    base: ScanConfig,
    overrides: dict[str, Any],
) -> ScanConfig:
    """Merge configuration with overrides.

    Args:
        base: Base configuration
        overrides: Dictionary of override values

    Returns:
        New ScanConfig with merged values
    """
    base_dict = base.model_dump()

    for key, value in overrides.items():
        if value is not None:
            base_dict[key] = value

    return ScanConfig(**base_dict)


def setup_logging(settings: AppSettings) -> None:
    """Configure logging based on settings."""
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    handlers: list[logging.Handler] = []

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format))
    handlers.append(console_handler)

    # File handler if configured
    if settings.log_file:
        settings.log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(settings.log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)

    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper()),
        handlers=handlers,
        force=True,
    )

    # Quiet down noisy libraries
    logging.getLogger("tree_sitter").setLevel(logging.WARNING)
