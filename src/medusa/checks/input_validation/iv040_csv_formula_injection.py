"""IV040: CSV Formula Injection.

Detects tool parameters related to CSV or spreadsheet data that lack formula injection
protection. Without validation, attackers can inject spreadsheet formulas starting with
=, +, -, or @ that execute when the data is opened in spreadsheet applications like
Excel or Google Sheets.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_CSV_PARAM_NAMES: set[str] = {
    "csv",
    "spreadsheet",
    "cell",
    "formula",
    "excel",
    "sheet",
    "cell_value",
    "data_entry",
    "worksheet",
    "column_value",
    "row_data",
}

# Pattern that blocks formula-triggering characters at the start of a value
_FORMULA_BLOCK_RE = re.compile(r"[=+\-@]|\\t|\\r|\\x09|\\x0[dD]")


class CsvFormulaInjectionCheck(BaseCheck):
    """CSV Formula Injection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            input_schema: dict | None = tool.get("inputSchema")

            if not input_schema or not isinstance(input_schema, dict):
                continue

            properties: dict = input_schema.get("properties", {})
            if not isinstance(properties, dict):
                continue

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue

                if param_name.lower().strip() not in _CSV_PARAM_NAMES:
                    continue

                if param_def.get("type") != "string":
                    continue

                has_enum = bool(param_def.get("enum"))
                if has_enum:
                    continue

                # Check if pattern blocks formula-triggering chars
                pattern_val: str = param_def.get("pattern", "")
                if pattern_val and _FORMULA_BLOCK_RE.search(pattern_val):
                    continue

                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=f"{tool_name}.{param_name}",
                        status_extended=(
                            f"Tool '{tool_name}' has CSV/spreadsheet parameter "
                            f"'{param_name}' without formula injection protection. "
                            f"Attackers can inject formulas (=, +, -, @) that "
                            f"execute in spreadsheet applications."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={pattern_val or 'N/A'}, "
                            f"no formula character rejection detected"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and snapshot.tools:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"No CSV formula injection risks detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
