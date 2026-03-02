"""INTG020: Inconsistent Tool Naming Convention.

Detects tools within the same server that use inconsistent naming
conventions (mixing camelCase, snake_case, kebab-case, PascalCase).
Inconsistency suggests poor governance and increases confusion.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Regex patterns for naming convention detection
_SNAKE_RE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)+$")
_KEBAB_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)+$")
_CAMEL_RE = re.compile(r"^[a-z][a-z0-9]*([A-Z][a-z0-9]*)+$")
_PASCAL_RE = re.compile(r"^[A-Z][a-z0-9]*([A-Z][a-z0-9]*)+$")


def _classify_naming_style(name: str) -> str:
    """Classify a tool name's naming convention."""
    # Strip any namespace prefix for classification
    if "::" in name:
        name = name.split("::")[-1]
    if "/" in name:
        name = name.split("/")[-1]
    if "." in name:
        name = name.split(".")[-1]

    if _SNAKE_RE.match(name):
        return "snake_case"
    if _KEBAB_RE.match(name):
        return "kebab-case"
    if _CAMEL_RE.match(name):
        return "camelCase"
    if _PASCAL_RE.match(name):
        return "PascalCase"

    # Single-word names: classify by character patterns
    if "_" in name and name == name.lower():
        return "snake_case"
    if "-" in name and name == name.lower():
        return "kebab-case"

    return "other"


class InconsistentNamingCheck(BaseCheck):
    """Inconsistent Tool Naming Convention."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Need at least 2 tools to detect inconsistency
        if len(snapshot.tools) < 2:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(snapshot.transport_type),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        "Server has fewer than 2 tools. Naming consistency check not applicable."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        style_map: dict[str, list[str]] = {}
        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            style = _classify_naming_style(tool_name)
            if style not in style_map:
                style_map[style] = []
            style_map[style].append(tool_name)

        # Remove "other" from consideration for consistency
        named_styles = {k: v for k, v in style_map.items() if k != "other"}

        if len(named_styles) > 1:
            evidence_parts: list[str] = []
            for style, tools in sorted(named_styles.items()):
                sample = ", ".join(tools[:3])
                evidence_parts.append(f"{style}: [{sample}]")

            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(snapshot.transport_type),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server "
                        f"'{snapshot.server_name}' uses "
                        f"{len(named_styles)} different "
                        f"naming conventions: "
                        f"{', '.join(sorted(named_styles))}."
                    ),
                    evidence=("; ".join(evidence_parts)),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
            style_used = next(iter(named_styles)) if named_styles else "unknown"
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(snapshot.transport_type),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"All tools use consistent "
                        f"naming convention "
                        f"({style_used}) across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
