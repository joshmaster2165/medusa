"""TP042: Version Variant Tool Names.

Detects when both a base tool name and a version-suffixed variant exist on the
same server (e.g., read_file and read_file_v2). This structural indicator
suggests potential tool mutation or rug-pull replacement attacks as described
in the Tool Mutation TTP.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_VERSION_SUFFIXES: list[str] = [
    "_v2",
    "_v3",
    "_v4",
    "_new",
    "_updated",
    "_latest",
    "_beta",
    "_fixed",
    "_patched",
    "_enhanced",
    "_improved",
    "_secure",
]


class VersionVariantToolNamesCheck(BaseCheck):
    """Version Variant Tool Names."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        tool_names = [t.get("name", "") for t in snapshot.tools]
        name_set = {n.lower() for n in tool_names}

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            name_lower = tool_name.lower()

            # Check if this tool is a versioned variant with a base that exists
            for suffix in _VERSION_SUFFIXES:
                if name_lower.endswith(suffix):
                    base = name_lower[: -len(suffix)]
                    if base in name_set:
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
                                    f"Tool '{tool_name}' is a versioned variant "
                                    f"of existing tool '{base}'. Both versions on "
                                    f"the same server may indicate a tool mutation "
                                    f"or rug-pull attack."
                                ),
                                evidence=(f"variant={tool_name}, base={base}, suffix={suffix}"),
                                remediation=meta.remediation,
                                owasp_mcp=meta.owasp_mcp,
                            )
                        )
                        break

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
                        f"No version variant tool name pairs detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
