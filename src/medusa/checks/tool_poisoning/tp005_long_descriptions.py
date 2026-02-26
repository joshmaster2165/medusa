"""TP-005: Flag abnormally long tool descriptions.

Tool descriptions longer than a configurable threshold (default 2000
characters) are flagged because excessive verbosity can:
- Hide injected instructions within walls of text
- Make manual review impractical
- Consume a disproportionate share of the LLM's context window
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Maximum description length before a warning is raised.
_DEFAULT_MAX_LENGTH: int = 2000


class LongDescriptionsCheck(BaseCheck):
    """Check for abnormally long tool descriptions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        max_length = _DEFAULT_MAX_LENGTH

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            description: str = tool.get("description", "")

            if not description:
                continue

            desc_length = len(description)

            if desc_length > max_length:
                # Provide a preview of the first and last portions
                preview_head = description[:120].replace("\n", " ")
                preview_tail = description[-80:].replace("\n", " ")
                preview = f"{preview_head} ... {preview_tail}"

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
                            f"Tool '{tool_name}' has an abnormally long "
                            f"description ({desc_length:,} characters, "
                            f"threshold is {max_length:,}). Long descriptions "
                            f"can hide injected instructions and consume "
                            f"excessive context window space."
                        ),
                        evidence=(
                            f"Length: {desc_length:,} chars "
                            f"(threshold: {max_length:,}). "
                            f"Preview: {preview}"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # PASS if all descriptions are within limits
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
                        f"All {len(snapshot.tools)} tool description(s) are "
                        f"within the {max_length:,}-character limit."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
