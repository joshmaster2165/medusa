"""DP034: Single Tool with Full Filesystem Control.

Detects a single tool that combines file read patterns AND write/delete
patterns, giving one tool full filesystem control. Tools that can both
read and modify/delete files create a privilege escalation and data
exfiltration risk since a single compromised tool call can access and
destroy data.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.filesystem import DESTRUCTIVE_TOOL_PATTERNS, FS_TOOL_PATTERNS

_READ_KEYWORDS: list[re.Pattern[str]] = [
    re.compile(r"\b(read|get|cat|view|show|list|fetch|retrieve)\b", re.IGNORECASE),
]

_WRITE_KEYWORDS: list[re.Pattern[str]] = [
    re.compile(r"\b(write|create|update|modify|overwrite|append|put|save)\b", re.IGNORECASE),
]


class FullFilesystemControlCheck(BaseCheck):
    """Single Tool with Full Filesystem Control."""

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
            description: str = tool.get("description", "") or ""
            check_text = f"{tool_name} {description}"

            # Check if tool is filesystem-related
            is_fs_tool = any(pattern.search(tool_name) for pattern in FS_TOOL_PATTERNS)
            if not is_fs_tool:
                fs_words = {"file", "filesystem", "directory", "folder", "path", "fs"}
                is_fs_tool = any(w in tool_name.lower() for w in fs_words)

            if not is_fs_tool:
                continue

            # Check for read capabilities
            has_read = any(pattern.search(check_text) for pattern in _READ_KEYWORDS) or any(
                pattern.search(check_text) for pattern in FS_TOOL_PATTERNS
            )

            # Check for destructive / write capabilities
            has_destructive = any(
                pattern.search(tool_name) for pattern in DESTRUCTIVE_TOOL_PATTERNS
            ) or any(pattern.search(check_text) for pattern in _WRITE_KEYWORDS)

            if has_read and has_destructive:
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
                            f"Tool '{tool_name}' combines file read and "
                            f"write/delete capabilities. A single tool with "
                            f"full filesystem control is a design flaw."
                        ),
                        evidence=(f"tool={tool_name}, has_read=True, has_destructive=True"),
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
                        f"No single tool with full filesystem control "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
