"""TP-004: Detect suspicious parameter names in tool input schemas.

Inspects every tool's ``inputSchema.properties`` for parameter names that
match known exfiltration-related names (callback_url, webhook, send_to, etc.)
as defined in ``medusa.utils.pattern_matching.SUSPICIOUS_PARAM_NAMES``.

The check walks nested ``properties`` and ``items`` to catch parameters buried
inside nested object or array schemas.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import SUSPICIOUS_PARAM_NAMES


def _collect_property_names(
    schema: dict[str, Any],
    prefix: str = "",
) -> list[tuple[str, str]]:
    """Recursively collect (dotted_path, raw_name) pairs from a JSON Schema.

    Walks ``properties``, ``items``, ``allOf``, ``anyOf``, and ``oneOf`` to
    ensure nested suspicious parameters are not missed.
    """
    results: list[tuple[str, str]] = []
    properties = schema.get("properties", {})

    for name, definition in properties.items():
        dotted = f"{prefix}.{name}" if prefix else name
        results.append((dotted, name))

        # Recurse into nested object schemas
        if isinstance(definition, dict):
            results.extend(_collect_property_names(definition, prefix=dotted))

    # Recurse into array item schemas
    items = schema.get("items")
    if isinstance(items, dict) and items:
        results.extend(_collect_property_names(items, prefix=prefix))

    # Recurse into combinators
    for combinator in ("allOf", "anyOf", "oneOf"):
        for sub_schema in schema.get(combinator, []):
            if isinstance(sub_schema, dict):
                results.extend(
                    _collect_property_names(sub_schema, prefix=prefix)
                )

    return results


class SuspiciousParamsCheck(BaseCheck):
    """Check tool input schemas for exfiltration-style parameter names."""

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
            input_schema: dict[str, Any] = tool.get("inputSchema", {})

            if not input_schema:
                continue

            all_params = _collect_property_names(input_schema)
            suspicious_hits: list[tuple[str, str]] = []

            for dotted_path, raw_name in all_params:
                normalised = raw_name.lower().strip()
                if normalised in SUSPICIOUS_PARAM_NAMES:
                    suspicious_hits.append((dotted_path, raw_name))

            if suspicious_hits:
                param_list = ", ".join(
                    f"'{path}'" for path, _ in suspicious_hits[:10]
                )
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
                            f"Tool '{tool_name}' has suspicious parameter(s) "
                            f"suggesting data exfiltration: {param_list}"
                        ),
                        evidence="; ".join(
                            f"{path} (matches '{raw}')"
                            for path, raw in suspicious_hits[:10]
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # PASS finding when no issues detected
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
                        f"No suspicious parameter names detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
