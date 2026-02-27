"""TP023: Description Language Mismatch.

Detects tool descriptions written in a different natural language than the server's configured
locale or the majority of other tool descriptions. Language mismatches can indicate copied
content from foreign attack toolkits or deliberate obfuscation of malicious instructions.

Heuristic: if tool name is pure ASCII but description contains a substantial proportion of
non-ASCII characters (>20% of chars), flag as a potential language mismatch.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_NON_ASCII_THRESHOLD: float = 0.20  # 20% non-ASCII chars in description


def _non_ascii_ratio(text: str) -> float:
    if not text:
        return 0.0
    non_ascii = sum(1 for c in text if ord(c) > 127)
    return non_ascii / len(text)


def _is_ascii_name(name: str) -> bool:
    return all(ord(c) < 128 for c in name)


class DescriptionLanguageMismatchCheck(BaseCheck):
    """Description Language Mismatch."""

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

            if not description or not _is_ascii_name(tool_name):
                continue

            ratio = _non_ascii_ratio(description)
            if ratio > _NON_ASCII_THRESHOLD:
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
                            f"Tool '{tool_name}' has ASCII name but description "
                            f"contains {ratio:.0%} non-ASCII characters, "
                            f"suggesting language mismatch or obfuscation."
                        ),
                        evidence=(
                            f"non-ASCII ratio={ratio:.0%} (threshold={_NON_ASCII_THRESHOLD:.0%})"
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
                        f"No description language mismatches detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
