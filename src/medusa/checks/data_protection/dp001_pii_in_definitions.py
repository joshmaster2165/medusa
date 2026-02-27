"""DP-001: Detect PII in MCP tool, resource, and prompt definitions.

Scans tool descriptions, resource descriptions/URIs, prompt descriptions,
and inputSchema fields (description, default, enum) for personally
identifiable information such as email addresses, phone numbers, SSNs,
credit card numbers, and IP addresses.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import PII_PATTERNS


class PiiInDefinitionsCheck(BaseCheck):
    """Check for PII embedded in tool/resource/prompt definitions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # --- Scan tools ---
        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            description: str = tool.get("description") or ""

            # Collect all text surfaces from this tool
            surfaces: list[tuple[str, str]] = []
            if description:
                surfaces.append(("description", description))

            # Scan inputSchema property descriptions, defaults, and enums
            input_schema = tool.get("inputSchema", {})
            schema_properties = input_schema.get("properties", {})
            for param_name, param_def in schema_properties.items():
                param_desc: str = param_def.get("description", "")
                if param_desc:
                    surfaces.append((f"parameter '{param_name}' description", param_desc))
                param_default = param_def.get("default")
                if param_default and isinstance(param_default, str):
                    surfaces.append((f"parameter '{param_name}' default", param_default))
                param_enum = param_def.get("enum", [])
                for enum_val in param_enum:
                    if isinstance(enum_val, str):
                        surfaces.append((f"parameter '{param_name}' enum value", enum_val))

            for surface_label, text in surfaces:
                pii_matches = _find_pii(text)
                if pii_matches:
                    match_list = ", ".join(f"{name}: '{val}'" for name, val in pii_matches[:5])
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
                                f"Tool '{tool_name}' {surface_label} contains PII: {match_list}"
                            ),
                            evidence=match_list,
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # --- Scan resources ---
        for resource in snapshot.resources:
            res_name: str = resource.get("name", "<unnamed>")
            res_desc: str = resource.get("description") or ""
            res_uri: str = str(resource.get("uri") or "")

            surfaces = []
            if res_desc:
                surfaces.append(("description", res_desc))
            if res_uri:
                surfaces.append(("uri", res_uri))

            for surface_label, text in surfaces:
                pii_matches = _find_pii(text)
                if pii_matches:
                    match_list = ", ".join(f"{name}: '{val}'" for name, val in pii_matches[:5])
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="resource",
                            resource_name=res_name,
                            status_extended=(
                                f"Resource '{res_name}' {surface_label} contains PII: {match_list}"
                            ),
                            evidence=match_list,
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # --- Scan prompts ---
        for prompt in snapshot.prompts:
            prompt_name: str = prompt.get("name", "<unnamed>")
            prompt_desc: str = prompt.get("description") or ""

            if prompt_desc:
                pii_matches = _find_pii(prompt_desc)
                if pii_matches:
                    match_list = ", ".join(f"{name}: '{val}'" for name, val in pii_matches[:5])
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="prompt",
                            resource_name=prompt_name,
                            status_extended=(
                                f"Prompt '{prompt_name}' description contains PII: {match_list}"
                            ),
                            evidence=match_list,
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # Emit PASS if items were checked but no issues found
        has_content = snapshot.tools or snapshot.resources or snapshot.prompts
        if not findings and has_content:
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
                        f"No PII detected across {len(snapshot.tools)} tool(s), "
                        f"{len(snapshot.resources)} resource(s), and "
                        f"{len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings


def _find_pii(text: str) -> list[tuple[str, str]]:
    """Return a list of (pii_type, matched_value) tuples found in text."""
    matches: list[tuple[str, str]] = []
    for pii_name, pattern in PII_PATTERNS:
        for match in pattern.finditer(text):
            matches.append((pii_name, match.group()))
    return matches
