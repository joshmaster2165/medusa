"""HARD016: Debug Mode Indicators.

Detects server configuration, environment variables, or launch arguments
that suggest debug mode is enabled, which may expose sensitive internals
in production environments.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

DEBUG_KEYS: set[str] = {
    "debug",
    "debug_mode",
    "verbose",
    "dev_mode",
    "development",
    "trace",
    "profiling",
    "node_env",
}

DEBUG_VALUES: set[str] = {
    "true",
    "1",
    "yes",
    "on",
    "debug",
    "development",
    "verbose",
    "trace",
}

DEBUG_ARGS: set[str] = {
    "--debug",
    "--verbose",
    "-v",
    "--dev",
    "--trace",
    "--profiling",
    "--development",
}


def _walk_config_for_debug(
    config: Any,
    _depth: int = 0,
) -> list[str]:
    """Walk config and return list of debug key matches."""
    matches: list[str] = []
    if _depth > 10:
        return matches
    if isinstance(config, dict):
        for key, value in config.items():
            if not isinstance(key, str):
                continue
            key_lower = key.lower()
            if key_lower in DEBUG_KEYS:
                val_str = str(value).lower().strip()
                if val_str in DEBUG_VALUES:
                    matches.append(f"{key}={value}")
            matches.extend(_walk_config_for_debug(value, _depth + 1))
    elif isinstance(config, list):
        for item in config:
            matches.extend(_walk_config_for_debug(item, _depth + 1))
    return matches


class DebugModeCheck(BaseCheck):
    """Debug Mode Indicators."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []
        evidence_parts: list[str] = []

        # Check environment variables
        if snapshot.env:
            for key, value in snapshot.env.items():
                key_lower = key.lower()
                val_lower = str(value).lower().strip()
                if key_lower in DEBUG_KEYS and (val_lower in DEBUG_VALUES):
                    evidence_parts.append(f"env:{key}={value}")

        # Check config_raw for debug keys
        if snapshot.config_raw:
            config_matches = _walk_config_for_debug(snapshot.config_raw)
            for match in config_matches:
                evidence_parts.append(f"config:{match}")

        # Check server args for debug flags
        if snapshot.args:
            for arg in snapshot.args:
                if arg.lower() in DEBUG_ARGS:
                    evidence_parts.append(f"arg:{arg}")

        if evidence_parts:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(snapshot.transport_type),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' "
                        f"has debug mode indicators "
                        f"enabled. Found "
                        f"{len(evidence_parts)} "
                        f"indicator(s)."
                    ),
                    evidence=", ".join(evidence_parts[:10]),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
            # Only emit PASS if there was data to check
            has_data = bool(snapshot.env or snapshot.config_raw or snapshot.args)
            if has_data:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.PASS,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=(snapshot.transport_type),
                        resource_type="server",
                        resource_name=snapshot.server_name,
                        status_extended=(
                            f"No debug mode indicators "
                            f"detected for server "
                            f"'{snapshot.server_name}'."
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        return findings
