"""TP-008: Unicode Homoglyph Tool Names.

Detects tool names that contain non-ASCII Unicode characters visually similar
to ASCII letters (e.g. Cyrillic 'а' vs Latin 'a').  These homoglyphs allow an
attacker to register a tool whose name looks identical to a trusted tool while
being a technically different identifier.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Unicode categories that are letters but not basic Latin
_SAFE_CATEGORIES = {"Ll", "Lu", "Lt", "Lm"}  # all letter categories
_ASCII_LETTER_RANGE = range(0x0020, 0x007F)


def _find_homoglyph_chars(name: str) -> list[str]:
    """Return descriptions of non-ASCII letter codepoints in *name*."""
    hits: list[str] = []
    for i, ch in enumerate(name):
        cp = ord(ch)
        if cp > 0x007E and unicodedata.category(ch) in _SAFE_CATEGORIES:
            uni_name = unicodedata.name(ch, "UNKNOWN")
            hits.append(f"U+{cp:04X} ({uni_name}) at pos {i}")
    return hits


class UnicodeHomoglyphToolNamesCheck(BaseCheck):
    """Unicode Homoglyph Tool Names."""

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
            hits = _find_homoglyph_chars(tool_name)
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
                            f"Tool name '{tool_name}' contains non-ASCII "
                            f"Unicode letters that may be homoglyphs: "
                            f"{'; '.join(hits[:5])}"
                        ),
                        evidence="; ".join(hits[:5]),
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
                        f"No Unicode homoglyph characters detected in "
                        f"{len(snapshot.tools)} tool name(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
