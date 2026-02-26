"""IV-002: Detect path-traversal risk in MCP tool input schemas.

Scans every tool's ``inputSchema`` for string parameters whose names match
known file-path identifiers (``path``, ``file``, ``directory``, etc.) and flags
those that lack a ``pattern`` constraint capable of blocking ``../`` traversal
sequences.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import PATH_PARAM_NAMES

# Patterns that, if present in a schema `pattern`, indicate the author at least
# attempted to block path traversal.
_TRAVERSAL_BLOCK_HINTS: list[re.Pattern[str]] = [
    re.compile(r"\.\.", re.IGNORECASE),         # literal ".." in regex
    re.compile(r"\\\.\\.", re.IGNORECASE),       # escaped "\.\." in regex
    re.compile(r"\^[a-zA-Z]", re.IGNORECASE),   # anchored to safe prefix
]


def _pattern_blocks_traversal(pattern: str) -> bool:
    """Heuristic: return *True* if the JSON Schema ``pattern`` appears to
    reject ``../`` sequences.  This is intentionally conservative -- only a
    genuine server-side check can provide real safety."""
    for hint in _TRAVERSAL_BLOCK_HINTS:
        if hint.search(pattern):
            return True
    # A pattern that doesn't allow '/' at all also blocks traversal
    if "/" not in pattern and "\\/" not in pattern:
        # A very restrictive pattern like ^[a-zA-Z0-9_]+$ implicitly blocks
        try:
            if not re.fullmatch(pattern, "../etc/passwd"):
                return True
        except re.error:
            pass
    return False


class PathTraversalCheck(BaseCheck):
    """Check for unconstrained file-path parameters in tool schemas."""

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
            input_schema: dict | None = tool.get("inputSchema")

            if not input_schema or not isinstance(input_schema, dict):
                continue

            properties: dict = input_schema.get("properties", {})
            if not isinstance(properties, dict):
                continue

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue

                if param_def.get("type") != "string":
                    continue

                normalised = param_name.lower().strip()
                if normalised not in PATH_PARAM_NAMES:
                    continue

                # Check if the schema has a pattern that blocks traversal
                pattern = param_def.get("pattern", "")
                has_enum = bool(param_def.get("enum"))

                if has_enum:
                    continue

                if pattern and _pattern_blocks_traversal(pattern):
                    continue

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
                            f"Tool '{tool_name}' has a path parameter "
                            f"'{param_name}' that does not constrain "
                            f"path-traversal sequences (e.g. '../'). "
                            f"An attacker could escape the intended "
                            f"directory."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={pattern or 'N/A'}, "
                            f"enum={param_def.get('enum', 'N/A')}"
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
                        f"No unconstrained path-traversal parameters "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
