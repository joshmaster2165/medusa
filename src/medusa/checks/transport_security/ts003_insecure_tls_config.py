"""TS-003: Insecure TLS Configuration.

Detects configuration specifying deprecated TLS versions (TLS 1.0, TLS 1.1,
SSLv2, SSLv3) which have known vulnerabilities.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import INSECURE_TLS_VERSIONS

_HTTP_TRANSPORTS = {"http", "sse"}

# Config keys that typically hold TLS version settings.
_TLS_VERSION_KEYS = {
    "tls_version",
    "ssl_version",
    "min_tls_version",
    "mintlsversion",
    "tlsversion",
    "sslversion",
    "tls_min_version",
    "ssl_protocol",
    "protocol",
    "min_protocol_version",
}


class InsecureTlsConfigCheck(BaseCheck):
    """Check for deprecated TLS version configuration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []

        # Check config_raw for TLS version settings
        if snapshot.config_raw:
            self._walk_config(snapshot.config_raw, "", meta, snapshot, findings)

        # Check env vars for TLS-related settings
        for env_key, env_value in snapshot.env.items():
            if env_key.lower() in _TLS_VERSION_KEYS:
                if env_value.lower().strip() in INSECURE_TLS_VERSIONS:
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="config",
                            resource_name=f"env.{env_key}",
                            status_extended=(
                                f"Environment variable '{env_key}' specifies "
                                f"deprecated TLS version '{env_value}' for "
                                f"server '{snapshot.server_name}'."
                            ),
                            evidence=f"{env_key} = {env_value}",
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
                        f"No deprecated TLS versions detected in configuration "
                        f"for server '{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings

    def _walk_config(
        self,
        config: dict,
        prefix: str,
        meta: CheckMetadata,
        snapshot: ServerSnapshot,
        findings: list[Finding],
    ) -> None:
        for key, value in config.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if key.lower() in _TLS_VERSION_KEYS and isinstance(value, str):
                if value.lower().strip() in INSECURE_TLS_VERSIONS:
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="config",
                            resource_name=full_key,
                            status_extended=(
                                f"Configuration key '{full_key}' specifies "
                                f"deprecated TLS version '{value}' for server "
                                f"'{snapshot.server_name}'."
                            ),
                            evidence=f"{full_key} = {value}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )
            elif isinstance(value, dict):
                self._walk_config(value, full_key, meta, snapshot, findings)
