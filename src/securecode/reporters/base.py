"""Base reporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from securecode.core.finding import ScanResult


class BaseReporter(ABC):
    """Base class for report generators."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Name of the output format (e.g., 'json', 'html')."""

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """File extension for output files (e.g., '.json', '.html')."""

    @abstractmethod
    def generate(self, result: ScanResult, output_path: Path) -> None:
        """Generate a report from scan results.

        Args:
            result: The scan results to report
            output_path: Path to write the report to
        """

    @abstractmethod
    def to_string(self, result: ScanResult) -> str:
        """Generate report as a string.

        Args:
            result: The scan results to report

        Returns:
            Report content as string
        """
