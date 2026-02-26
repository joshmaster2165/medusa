"""INTG-004: Missing Integrity Verification for Tool Definitions.

Detects MCP servers that expose tools but have no integrity verification
baseline (hashes, checksums, or integrity block) in their configuration.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Config keys indicating an integrity baseline is present.
_INTEGRITY_BASELINE_KEYS: set[str] = {
    "baseline",
    "hashes",
    "tool_hashes",
    "integrity",
    "checksums",
    "checksum",
    "sha256",
    "digests",
}


def _config_has_baseline(config: dict | None) -> bool:
    """Check if the config contains any integrity baseline keys."""
    if not config:
        return False

    def _search(d: dict) -> bool:
        for key, value in d.items():
            if key.lower() in _INTEGRITY_BASELINE_KEYS:
                return True
            if isinstance(value, dict) and _search(value):
                return True
        return False

    return _search(config)


class MissingIntegrityVerificationCheck(BaseCheck):
    """Check for missing integrity verification baseline for tool definitions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # Only relevant if the server exposes tools.
        if not snapshot.tools:
            return findings

        has_baseline = _config_has_baseline(snapshot.config_raw)

        if has_baseline:
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
                        f"Server '{snapshot.server_name}' has an integrity "
                        f"verification baseline for its "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' exposes "
                        f"{len(snapshot.tools)} tool(s) but has no integrity "
                        f"verification baseline in its configuration. Tool "
                        f"definitions can be modified without detection."
                    ),
                    evidence=(
                        f"tools_count={len(snapshot.tools)}, "
                        f"config_keys={list((snapshot.config_raw or {}).keys())}"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
