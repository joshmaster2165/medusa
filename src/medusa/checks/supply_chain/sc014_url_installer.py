"""SC-014: Executable from URL Without Hash Pinning.

Detects tools that accept URLs for code/data loading or execution without
requiring integrity verification via hash or checksum parameters.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.schema import HASH_INTEGRITY_PARAMS, URL_PARAM_NAMES

_EXEC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b(execute|run|install|load|import|eval|deploy|apply|launch|start)\b", re.IGNORECASE
    ),
]


class UrlInstallerCheck(BaseCheck):
    """Detect tools that load executables from URLs without integrity checks."""

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
            tool_name = tool.get("name", "<unnamed>")
            description = tool.get("description", "")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {})
            param_names_lower = {p.lower() for p in properties}

            # Check for URL parameter
            has_url_param = bool(param_names_lower & URL_PARAM_NAMES)

            # Check for execution indicator in name or description
            combined = f"{tool_name} {description}"
            has_exec = any(p.search(combined) for p in _EXEC_PATTERNS)

            if not (has_url_param and has_exec):
                continue

            # Check for hash/integrity parameter
            has_hash = bool(param_names_lower & HASH_INTEGRITY_PARAMS)

            if not has_hash:
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
                            f"Tool '{tool_name}' accepts a URL parameter and performs "
                            f"execution/loading operations but does not require a hash or "
                            f"checksum parameter for integrity verification. An attacker "
                            f"could supply a malicious URL to execute untrusted code."
                        ),
                        evidence=(
                            f"url_params={param_names_lower & URL_PARAM_NAMES}, hash_params=none"
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
                        f"No URL-based execution tools without integrity verification "
                        f"found across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
