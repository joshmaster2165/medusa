"""TP028: Unicode Homoglyph in Identifiers.

Detects non-ASCII characters in tool names and parameter names. Attackers use
Unicode homoglyphs (e.g. Cyrillic 'e' instead of Latin 'e', or zero-width
characters) to create visually identical but functionally different tool names,
enabling tool shadowing and impersonation attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Zero-width and invisible Unicode characters that are always suspicious.
_ZERO_WIDTH_CHARS: set[int] = {
    0x200B,  # Zero Width Space
    0x200C,  # Zero Width Non-Joiner
    0x200D,  # Zero Width Joiner
    0xFEFF,  # Zero Width No-Break Space (BOM)
    0x00AD,  # Soft Hyphen
    0x2060,  # Word Joiner
}


def _find_non_ascii(text: str) -> list[tuple[int, str, int]]:
    """Find non-ASCII characters in text.

    Returns a list of (index, character, codepoint) tuples.
    """
    issues: list[tuple[int, str, int]] = []
    for i, char in enumerate(text):
        codepoint = ord(char)
        if codepoint > 127:
            issues.append((i, char, codepoint))
    return issues


def _find_zero_width(text: str) -> list[tuple[int, str, int]]:
    """Find zero-width / invisible characters in text.

    Returns a list of (index, character, codepoint) tuples.
    """
    issues: list[tuple[int, str, int]] = []
    for i, char in enumerate(text):
        codepoint = ord(char)
        if codepoint in _ZERO_WIDTH_CHARS:
            issues.append((i, char, codepoint))
    return issues


def _format_char_evidence(chars: list[tuple[int, str, int]]) -> str:
    """Format a list of character issues into a readable evidence string."""
    parts: list[str] = []
    for idx, char, codepoint in chars[:5]:  # Limit to 5 examples
        parts.append(f"pos={idx} char=U+{codepoint:04X} ('{char}')")
    suffix = f" (+{len(chars) - 5} more)" if len(chars) > 5 else ""
    return ", ".join(parts) + suffix


class UnicodeHomoglyphAttackCheck(BaseCheck):
    """Unicode Homoglyph in Identifiers."""

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

            # Check the tool name itself.
            non_ascii = _find_non_ascii(tool_name)
            zero_width = _find_zero_width(tool_name)

            if zero_width:
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
                            f"Tool name '{tool_name}' contains {len(zero_width)} "
                            f"zero-width/invisible character(s). This is a strong "
                            f"indicator of a homoglyph impersonation attack."
                        ),
                        evidence=f"tool_name: {_format_char_evidence(zero_width)}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )
            elif non_ascii:
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
                            f"Tool name '{tool_name}' contains {len(non_ascii)} "
                            f"non-ASCII character(s). These may be Unicode homoglyphs "
                            f"designed to impersonate a legitimate tool."
                        ),
                        evidence=f"tool_name: {_format_char_evidence(non_ascii)}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

            # Check parameter names in the input schema.
            input_schema: dict = tool.get("inputSchema", {}) or {}
            properties: dict = input_schema.get("properties", {}) or {}

            for param_name in properties:
                param_non_ascii = _find_non_ascii(param_name)
                param_zero_width = _find_zero_width(param_name)

                if param_zero_width:
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
                                f"Parameter '{param_name}' in tool '{tool_name}' "
                                f"contains {len(param_zero_width)} zero-width/invisible "
                                f"character(s)."
                            ),
                            evidence=(
                                f"param={param_name}: {_format_char_evidence(param_zero_width)}"
                            ),
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )
                elif param_non_ascii:
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
                                f"Parameter '{param_name}' in tool '{tool_name}' "
                                f"contains {len(param_non_ascii)} non-ASCII "
                                f"character(s) that may be Unicode homoglyphs."
                            ),
                            evidence=(
                                f"param={param_name}: {_format_char_evidence(param_non_ascii)}"
                            ),
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        if not findings:
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
                        f"No Unicode homoglyphs detected in tool or parameter names "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
