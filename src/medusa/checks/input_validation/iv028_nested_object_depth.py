"""IV028: Excessive Nested Object Depth.

Detects tool parameters that allow deeply nested object structures without depth limits.
Excessive nesting can hide malicious payloads deep in the structure, evade validation, and cause
stack overflow or excessive memory consumption during parsing.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_MAX_SAFE_DEPTH: int = 5


def _measure_depth(schema: dict, current: int = 0) -> int:
    """Recursively measure the maximum nesting depth of a JSON schema."""
    if not isinstance(schema, dict):
        return current

    max_depth = current
    # Recurse into object properties
    for prop_def in schema.get("properties", {}).values():
        max_depth = max(max_depth, _measure_depth(prop_def, current + 1))
    # Recurse into array items
    items = schema.get("items")
    if isinstance(items, dict):
        max_depth = max(max_depth, _measure_depth(items, current + 1))
    # Recurse into anyOf / oneOf / allOf
    for combiner in ("anyOf", "oneOf", "allOf"):
        for sub in schema.get(combiner, []):
            max_depth = max(max_depth, _measure_depth(sub, current + 1))
    return max_depth


class NestedObjectDepthCheck(BaseCheck):
    """Excessive Nested Object Depth."""

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

            depth = _measure_depth(input_schema)
            if depth <= _MAX_SAFE_DEPTH:
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
                    resource_name=tool_name,
                    status_extended=(
                        f"Tool '{tool_name}' inputSchema has nesting depth of {depth} "
                        f"(limit: {_MAX_SAFE_DEPTH}). Deep nesting can hide malicious "
                        f"payloads and cause stack overflows during parsing."
                    ),
                    evidence=(
                        f"tool={tool_name}, measured_depth={depth}, "
                        f"max_safe_depth={_MAX_SAFE_DEPTH}"
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
                        f"All tool schemas have acceptable nesting depth (<= {_MAX_SAFE_DEPTH}) "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
