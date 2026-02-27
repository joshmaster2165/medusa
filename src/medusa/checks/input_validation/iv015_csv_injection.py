"""IV015: CSV Injection Risk.

Detects tool parameters whose output may be rendered in CSV format without sanitization.
Parameters containing formula prefixes (=, +, -, @) can execute formulas when the CSV is opened
in spreadsheet applications, enabling data exfiltration and code execution.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.schema import CSV_PARAM_NAMES

# A safe pattern should block formula-prefix characters: = + - @
_CSV_BLOCK_RE = re.compile(r"[=+\-@]")


class CsvInjectionCheck(BaseCheck):
    """CSV Injection Risk."""

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

                if param_def.get("type") != "string":
                    continue

                if param_name.lower().strip() not in CSV_PARAM_NAMES:
                    continue

                pattern_val: str = param_def.get("pattern", "")
                has_enum = bool(param_def.get("enum"))

                if has_enum:
                    continue
                # Pattern is safe if it explicitly excludes formula-prefix chars
                if pattern_val and not _CSV_BLOCK_RE.search(pattern_val):
                    # Pattern does not contain formula chars - likely restricts to safe chars
                    # Only flag if pattern appears overly permissive (empty or .*)
                    if pattern_val not in (".*", "^.*$", ".+", "^.+$"):
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
                            f"Tool '{tool_name}' CSV parameter '{param_name}' does not block "
                            f"formula-prefix characters (=, +, -, @). "
                            f"Injected formulas execute when the CSV is opened in a spreadsheet."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={param_def.get('pattern', 'N/A')}, "
                            f"enum={param_def.get('enum', 'N/A')}"
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
                        f"No unconstrained CSV injection parameters detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
