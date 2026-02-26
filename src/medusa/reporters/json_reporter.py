"""JSON report generator."""

from __future__ import annotations

from medusa.core.models import ScanResult
from medusa.reporters.base import BaseReporter


class JsonReporter(BaseReporter):
    """Generate JSON report output."""

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def generate(self, result: ScanResult) -> str:
        return result.model_dump_json(indent=self.indent)
