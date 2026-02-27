"""Base reporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

import click
from rich.console import Console

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

    def print_to_console(self, result: ScanResult, console: Console) -> None:
        """Print report directly to the console using rich.

        Subclasses that produce rich output should override this.
        The default implementation falls back to generate() + click.echo().
        """
        click.echo(self.generate(result))
