"""TP-009: Base64-Encoded Instructions in Descriptions.

Scans tool descriptions for Base64 strings. Matched strings are decoded and
scanned for prompt-injection phrases.  A hit on the decoded content is a
strong signal that the encoded payload contains hidden directives.
"""

from __future__ import annotations

import base64
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.injection import BASE64_PATTERN
from medusa.utils.text_analysis import find_injection_phrases


def _decode_if_injection(encoded: str) -> str | None:
    """Decode a Base64 string and return it if it contains injection phrases."""
    try:
        # Pad if necessary
        padded = encoded + "=" * (-len(encoded) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
        if find_injection_phrases(decoded):
            return decoded[:200]
    except Exception:
        pass
    return None


class Base64EncodedInstructionsCheck(BaseCheck):
    """Base64-Encoded Instructions in Descriptions."""

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

            hits: list[str] = []
            for match in BASE64_PATTERN.finditer(description):
                decoded = _decode_if_injection(match.group())
                if decoded is not None:
                    hits.append(f"Decoded payload: {decoded!r}")

            if hits:
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
                            f"Tool '{tool_name}' description contains "
                            f"Base64-encoded injection instructions."
                        ),
                        evidence="; ".join(hits[:3]),
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
                        f"No Base64-encoded injection instructions detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
