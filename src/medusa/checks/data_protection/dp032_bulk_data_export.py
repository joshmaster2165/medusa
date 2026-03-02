"""DP032: Bulk Data Export Tool.

Detects tools that allow bulk data export, dump, or backup operations
without pagination or limit constraints. Unbounded bulk export tools
can leak entire datasets to connected LLM clients.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

BULK_INDICATORS_NAME: set[str] = {
    "dump",
    "export",
    "backup",
    "bulk",
    "all",
    "mass",
    "batch_get",
    "download_all",
    "extract_all",
}

BULK_INDICATORS_DESC: set[str] = {
    "all records",
    "entire database",
    "full dump",
    "complete export",
    "bulk download",
    "mass extract",
    "all data",
    "all users",
    "all entries",
    "all rows",
    "every record",
    "full backup",
    "complete backup",
}

PAGINATION_PARAMS: set[str] = {
    "limit",
    "page",
    "offset",
    "page_size",
    "max_results",
    "cursor",
    "per_page",
    "page_number",
    "start",
    "count",
}


def _name_is_bulk(tool_name: str) -> bool:
    """Check if tool name contains bulk data indicators."""
    tokens = set(tool_name.lower().replace("-", "_").split("_"))
    return bool(tokens & BULK_INDICATORS_NAME)


def _desc_is_bulk(description: str) -> str | None:
    """Return matched bulk phrase from description, or None."""
    desc_lower = description.lower()
    for phrase in BULK_INDICATORS_DESC:
        if phrase in desc_lower:
            return phrase
    return None


def _has_pagination(tool: dict) -> bool:
    """Check if tool schema has pagination parameters."""
    input_schema = tool.get("inputSchema", {})
    if not isinstance(input_schema, dict):
        return False
    properties = input_schema.get("properties", {})
    if not isinstance(properties, dict):
        return False
    param_names = {p.lower() for p in properties}
    return bool(param_names & PAGINATION_PARAMS)


class BulkDataExportCheck(BaseCheck):
    """Bulk Data Export Tool."""

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
            description: str = tool.get("description", "")

            is_bulk_name = _name_is_bulk(tool_name)
            bulk_phrase = _desc_is_bulk(description)

            if not is_bulk_name and not bulk_phrase:
                continue

            if _has_pagination(tool):
                continue

            evidence_parts = []
            if is_bulk_name:
                evidence_parts.append("name_match=true")
            if bulk_phrase:
                evidence_parts.append(f"desc_match='{bulk_phrase}'")
            evidence_parts.append("pagination=missing")

            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(snapshot.transport_type),
                    resource_type="tool",
                    resource_name=tool_name,
                    status_extended=(
                        f"Tool '{tool_name}' appears to be "
                        f"a bulk data export tool without "
                        f"pagination or limit constraints."
                    ),
                    evidence=", ".join(evidence_parts),
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
                        "No unbounded bulk export tools "
                        f"detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
