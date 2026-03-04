"""TP051: Read-Only Claim with Write Schema.

Detects tools claiming read-only or safe behavior in their description but
having write, delete, or execute parameters in their schema. This is a
concrete structural mismatch indicating capability misrepresentation.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_READONLY_CLAIMS: list[re.Pattern[str]] = [
    re.compile(r"\bread[-\s]?only\b", re.IGNORECASE),
    re.compile(r"\bsafe(ly)?\s+(read|view|inspect|browse)\b", re.IGNORECASE),
    re.compile(r"\bno\s+(write|modify|delete|change|side.?effect)\b", re.IGNORECASE),
    re.compile(r"\bdoes\s+not\s+(modify|write|delete|change)\b", re.IGNORECASE),
    re.compile(r"\bnon[-\s]?destructive\b", re.IGNORECASE),
]

_WRITE_PARAM_NAMES: set[str] = {
    "write",
    "delete",
    "remove",
    "execute",
    "command",
    "shell",
    "modify",
    "update",
    "overwrite",
    "create",
    "drop",
    "truncate",
    "destroy",
    "kill",
    "exec",
    "run",
    "script",
    "bash",
    "purge",
    "wipe",
}


class ReadonlyClaimWriteSchemaCheck(BaseCheck):
    """Read-Only Claim with Write Schema."""

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

            if not description:
                continue

            # Check for read-only claims in description
            has_readonly_claim = any(p.search(description) for p in _READONLY_CLAIMS)
            if not has_readonly_claim:
                continue

            # Extract parameter names from schema
            schema = tool.get("inputSchema") or tool.get("parameters", {})
            properties = schema.get("properties", {})
            param_names = {k.lower() for k in properties}

            write_params = param_names & _WRITE_PARAM_NAMES
            if write_params:
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
                            f"Tool '{tool_name}' claims read-only "
                            f"behavior but has write/execute "
                            f"parameters: "
                            f"{', '.join(sorted(write_params))}. "
                            f"This misrepresents the tool's actual "
                            f"capabilities."
                        ),
                        evidence=(f"readonly_claim=True, write_params={sorted(write_params)}"),
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
                        f"No read-only claim / write schema mismatches "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
