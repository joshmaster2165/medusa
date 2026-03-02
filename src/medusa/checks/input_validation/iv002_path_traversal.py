"""IV-002: Detect path-traversal risk in MCP tool input schemas.

Scans every tool's ``inputSchema`` for string parameters whose names match
known file-path identifiers (``path``, ``file``, ``directory``, etc.) and flags
those that lack a ``pattern`` constraint capable of blocking ``../`` traversal
sequences.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Severity, Status
from medusa.utils.heuristics import (
    PATH_TRAVERSAL_VECTORS,
    PatternStrength,
    assess_pattern_strength,
    pattern_block_percentage,
)
from medusa.utils.pattern_matching import PATH_PARAM_NAMES


class PathTraversalCheck(BaseCheck):
    """Check for unconstrained file-path parameters in tool schemas."""

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

                normalised = param_name.lower().strip()
                if normalised not in PATH_PARAM_NAMES:
                    continue

                # Check if the schema constrains the value
                has_enum = bool(param_def.get("enum"))
                if has_enum:
                    continue  # Enum is genuinely constrained

                pattern = param_def.get("pattern", "")
                if pattern:
                    strength = assess_pattern_strength(
                        pattern, PATH_TRAVERSAL_VECTORS
                    )
                    if strength == PatternStrength.STRONG:
                        continue  # Pattern blocks ≥90% of traversal vectors

                    if strength == PatternStrength.MODERATE:
                        pct = pattern_block_percentage(
                            pattern, PATH_TRAVERSAL_VECTORS
                        )
                        findings.append(
                            Finding(
                                check_id=meta.check_id,
                                check_title=meta.title,
                                status=Status.FAIL,
                                severity=Severity.MEDIUM,
                                server_name=snapshot.server_name,
                                server_transport=snapshot.transport_type,
                                resource_type="tool",
                                resource_name=f"{tool_name}.{param_name}",
                                status_extended=(
                                    f"Tool '{tool_name}' parameter "
                                    f"'{param_name}' has a pattern constraint "
                                    f"but it only blocks {pct}% of test "
                                    f"path-traversal payloads."
                                ),
                                evidence=(
                                    f"param={param_name}, type=string, "
                                    f"pattern={pattern!r}, "
                                    f"strength={strength}, blocked={pct}%"
                                ),
                                remediation=meta.remediation,
                                owasp_mcp=meta.owasp_mcp,
                            )
                        )
                        continue

                # WEAK pattern or no constraint — full severity
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
                            f"Tool '{tool_name}' has a path parameter "
                            f"'{param_name}' that does not adequately "
                            f"constrain path-traversal sequences. "
                            f"An attacker could escape the intended "
                            f"directory."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={pattern or 'N/A'}, "
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
                        f"No unconstrained path-traversal parameters "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
