"""SC007: Native Binary Dependencies.

Detects MCP server dependencies that contain prebuilt native binaries. Prebuilt binaries cannot
be audited from source code and may contain hidden functionality.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_NATIVE_KEYS: set[str] = {
    "native",
    "binary",
    "compile",
    "gyp",
    "node_gyp",
    "prebuild",
    "prebuilt",
    "napi",
    "ffi",
    "addon",
    "binding",
}


def _walk_config(config: Any, keys: set[str], _depth: int = 0) -> bool:
    if _depth > 10:
        return False
    if isinstance(config, dict):
        for key in config:
            if isinstance(key, str) and key.lower() in keys:
                return True
            if _walk_config(config[key], keys, _depth + 1):
                return True
    elif isinstance(config, list):
        for item in config:
            if _walk_config(item, keys, _depth + 1):
                return True
    return False


class NativeBinaryDependenciesCheck(BaseCheck):
    """Native Binary Dependencies."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if snapshot.transport_type != "stdio" or not snapshot.command:
            return findings

        has_native = (
            _walk_config(snapshot.config_raw, _NATIVE_KEYS) if snapshot.config_raw else False
        )
        args_str = " ".join(snapshot.args).lower()
        has_native_arg = any(k in args_str for k in ("node-gyp", "prebuild", "napi", "ffi"))

        if has_native or has_native_arg:
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
                    status_extended="Native binary dependency indicators detected.",
                    evidence="native_indicators=True",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
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
                    status_extended="No native binary dependency indicators detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
