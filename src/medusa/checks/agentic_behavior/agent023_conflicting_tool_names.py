"""AGENT-023: Conflicting Tool Names.

Detects multiple tools with semantically similar names that could cause
confusion or shadowing. Normalized name collisions may lead LLM agents
to invoke the wrong tool, especially when tool names differ only by
prefix, suffix, or delimiter style. Also detects exact duplicate tool
registrations.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Severity, Status

# Prefixes and suffixes to strip during normalization.
_STRIP_PREFIXES = ("get_", "set_", "create_", "do_", "fetch_", "update_")
_STRIP_SUFFIXES = ("_v2", "_v3", "_new", "_old", "_legacy", "_beta", "_latest")


def _normalize_tool_name(name: str) -> str:
    """Normalize a tool name for collision detection."""
    normalized = name.lower().replace("-", "_")

    # Strip common prefixes
    for prefix in _STRIP_PREFIXES:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break

    # Strip common suffixes
    for suffix in _STRIP_SUFFIXES:
        if normalized.endswith(suffix):
            normalized = normalized[: -len(suffix)]
            break

    return normalized


class ConflictingToolNamesCheck(BaseCheck):
    """Conflicting Tool Names."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools or len(snapshot.tools) < 2:
            return findings

        # Check for exact duplicates
        raw_names: list[str] = []
        seen_raw: dict[str, int] = {}
        for tool in snapshot.tools:
            name = tool.get("name", "unknown")
            raw_names.append(name)
            seen_raw[name] = seen_raw.get(name, 0) + 1

        for name, count in seen_raw.items():
            if count > 1:
                findings.append(Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="tool",
                    resource_name=name,
                    status_extended=(
                        f"Tool name '{name}' is registered {count} times "
                        f"(exact duplicate). This causes ambiguity in tool "
                        f"selection."
                    ),
                    evidence=f"Duplicate tool name: '{name}' x{count}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                ))

        # Check for normalized collisions (excluding exact duplicates)
        normalized_map: dict[str, list[str]] = defaultdict(list)
        for name in raw_names:
            norm = _normalize_tool_name(name)
            normalized_map[norm].append(name)

        for norm, original_names in normalized_map.items():
            # Only flag if there are distinct original names that collide
            unique_names = sorted(set(original_names))
            if len(unique_names) > 1:
                findings.append(Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Tools {unique_names} have semantically similar names "
                        f"(normalized to '{norm}'). This may cause LLM confusion "
                        f"or tool shadowing."
                    ),
                    evidence=(
                        f"Normalized collision: "
                        f"{' vs '.join(unique_names)} -> '{norm}'"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                ))

        if not findings:
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended="No conflicting or duplicate tool names detected.",
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))
        return findings
