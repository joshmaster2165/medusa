"""TP020: Conflicting Parameter Descriptions.

Detects tool parameters whose descriptions contradict the stated purpose of the tool. For
example, a tool described as "read-only file viewer" with a parameter described as "path to
write output" indicates a mismatch that may signal deceptive intent.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Keywords that indicate read-only / safe operation in tool description
_READ_ONLY_KEYWORDS: list[re.Pattern[str]] = [
    re.compile(r"\bread[- _]?only\b", re.IGNORECASE),
    re.compile(r"\bview(?:er)?\b", re.IGNORECASE),
    re.compile(r"\binspect\b", re.IGNORECASE),
    re.compile(r"\bfetch\b", re.IGNORECASE),
    re.compile(r"\bget\b", re.IGNORECASE),
    re.compile(r"\blist\b", re.IGNORECASE),
]

# Keywords that indicate write / destructive action in param descriptions
_WRITE_KEYWORDS: list[re.Pattern[str]] = [
    re.compile(r"\bwrite\b", re.IGNORECASE),
    re.compile(r"\bdelete\b", re.IGNORECASE),
    re.compile(r"\bremove\b", re.IGNORECASE),
    re.compile(r"\bmodif(?:y|ied)\b", re.IGNORECASE),
    re.compile(r"\boverwrite\b", re.IGNORECASE),
    re.compile(r"\bexecute\b", re.IGNORECASE),
    re.compile(r"\bupload\b", re.IGNORECASE),
    re.compile(r"\bsend\b", re.IGNORECASE),
]


def _is_read_only_tool(tool_desc: str) -> bool:
    return any(p.search(tool_desc) for p in _READ_ONLY_KEYWORDS)


def _has_write_param(param_desc: str) -> list[str]:
    return [m.group() for p in _WRITE_KEYWORDS for m in p.finditer(param_desc)]


class ConflictingParameterDescriptionsCheck(BaseCheck):
    """Conflicting Parameter Descriptions."""

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
            tool_desc: str = tool.get("description", "")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}

            if not _is_read_only_tool(tool_desc):
                continue

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue
                param_desc = param_def.get("description", "")
                write_hits = _has_write_param(param_desc)
                if write_hits:
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
                                f"Tool '{tool_name}' appears read-only but "
                                f"parameter '{param_name}' description implies "
                                f"write/destructive action: "
                                f"{', '.join(write_hits[:3])}"
                            ),
                            evidence=(
                                f"Tool desc implies read-only; param '{param_name}' "
                                f"uses write keywords: {', '.join(write_hits[:3])}"
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
                        f"No conflicting parameter descriptions detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
