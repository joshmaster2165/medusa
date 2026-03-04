"""TP036: ANSI Escape Injection in Tool Descriptions.

Detects ANSI/terminal escape sequences (CSI, OSC, raw ESC bytes) in tool
or parameter descriptions. These control characters can hide malicious
instructions from terminal display while remaining visible to LLMs,
enabling steganographic prompt injection.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_ANSI_ESCAPE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\\x1b\["),  # Escaped CSI sequence
    re.compile(r"\\033\["),  # Octal CSI sequence
    re.compile(r"\\e\["),  # Short escape CSI
    re.compile(r"\\x1b\]"),  # Escaped OSC sequence
    re.compile(r"\\x0?7\b"),  # BEL character
    re.compile(r"\\x08"),  # Backspace
]

# Raw control characters that should never appear in descriptions
_RAW_CONTROL_CHARS: set[int] = {
    0x1B,  # ESC
    0x07,  # BEL
    0x08,  # BS (backspace)
    0x7F,  # DEL
    0x9B,  # CSI (8-bit)
    0x9D,  # OSC (8-bit)
}


class AnsiEscapeInjectionCheck(BaseCheck):
    """ANSI Escape Injection in Tool Descriptions."""

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
            # Combine tool description + all parameter descriptions
            parts: list[str] = [tool.get("description", "") or ""]
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            for param_def in properties.values():
                if isinstance(param_def, dict):
                    parts.append(param_def.get("description", "") or "")
            all_text = " ".join(parts)

            if not all_text.strip():
                continue

            matched: list[str] = []

            # Check regex patterns against all_text
            for pattern in _ANSI_ESCAPE_PATTERNS:
                hits = pattern.findall(all_text)
                if hits:
                    matched.extend(hits[:3])

            # Check for raw control characters
            for char in all_text:
                if ord(char) in _RAW_CONTROL_CHARS:
                    matched.append(f"raw_control_0x{ord(char):02X}")

            if matched:
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
                            f"Tool '{tool_name}' contains ANSI escape "
                            f"sequences ({len(matched)} match(es)). "
                            f"Terminal control characters may hide "
                            f"malicious instructions."
                        ),
                        evidence=f"ansi_matches={matched[:5]}",
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
                        f"No ANSI escape injection detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
