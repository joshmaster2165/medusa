"""Base reporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from medusa.core.models import ScanResult


class BaseReporter(ABC):
    """Base class for all report generators."""

    @abstractmethod
    def generate(self, result: ScanResult) -> str:
        """Generate a report string from scan results."""
        ...

    def write(self, result: ScanResult, output_path: str) -> None:
        """Generate and write report to a file."""
        content = self.generate(result)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
