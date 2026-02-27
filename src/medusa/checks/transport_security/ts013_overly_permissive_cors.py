"""TS013: Overly Permissive CORS.

Detects MCP servers with CORS configuration that allows all origins (Access-Control-Allow-
Origin: *) or reflects the request origin. Overly permissive CORS enables any website to make
authenticated requests to the MCP server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_CORS_ORIGIN_KEYS = {
    "access_control_allow_origin",
    "cors_origin",
    "allowed_origins",
    "allow_origin",
    "cors_origins",
}
_WILDCARD_VALUES = {"*", "all", "any", "null"}


def _find_permissive_cors(config: dict, depth: int = 0) -> str | None:
    if depth > 10:
        return None
    for k, v in config.items():
        if k.lower() in _CORS_ORIGIN_KEYS:
            if isinstance(v, str) and v.strip() in _WILDCARD_VALUES:
                return f"'{k}' = '{v}' (wildcard origin)"
            if isinstance(v, list) and any(str(o).strip() in _WILDCARD_VALUES for o in v):
                return f"'{k}' contains wildcard origin"
        if isinstance(v, dict):
            result = _find_permissive_cors(v, depth + 1)
            if result:
                return result
    return None


class OverlyPermissiveCorsCheck(BaseCheck):
    """Overly Permissive CORS."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        evidence = _find_permissive_cors(snapshot.config_raw or {})
        if evidence:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="cors.origin",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has overly permissive CORS: {evidence}. "
                        f"Any website can make authenticated requests to this server."
                    ),
                    evidence=evidence,
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        return [
            Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="config",
                resource_name="cors.origin",
                status_extended=(
                    f"Server '{snapshot.server_name}' CORS origin policy appears appropriately"
                    f"restricted."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
