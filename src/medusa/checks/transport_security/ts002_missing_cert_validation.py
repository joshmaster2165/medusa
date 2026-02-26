"""TS-002: Missing Certificate Validation.

Detects configuration that disables TLS certificate verification, which
enables man-in-the-middle attacks even when HTTPS is used.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import CERT_DISABLE_CONFIG_KEYS, CERT_DISABLE_ENV_VARS

_HTTP_TRANSPORTS = {"http", "sse"}

# Values that indicate cert validation is disabled.
_DISABLE_VALUES = {"0", "false", "no", "off", "disable", "disabled", ""}


def _walk_config_for_cert_disable(config: dict) -> list[tuple[str, str]]:
    """Walk config dict looking for keys that disable cert validation.

    Returns list of (key_path, value) tuples.
    """
    hits: list[tuple[str, str]] = []

    def _walk(obj: dict, prefix: str = "") -> None:
        for key, value in obj.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if key.lower() in CERT_DISABLE_CONFIG_KEYS:
                str_value = str(value).lower().strip()
                if str_value in _DISABLE_VALUES:
                    hits.append((full_key, str(value)))
            if isinstance(value, dict):
                _walk(value, full_key)

    _walk(config)
    return hits


class MissingCertValidationCheck(BaseCheck):
    """Check for disabled TLS certificate validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []

        # Check config_raw for cert disable keys
        if snapshot.config_raw:
            hits = _walk_config_for_cert_disable(snapshot.config_raw)
            for key_path, value in hits:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="config",
                        resource_name=key_path,
                        status_extended=(
                            f"Server '{snapshot.server_name}' has TLS certificate "
                            f"validation disabled via '{key_path} = {value}'. "
                            f"This allows man-in-the-middle attacks."
                        ),
                        evidence=f"{key_path} = {value}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Check env vars
        for env_key, env_value in snapshot.env.items():
            if env_key in CERT_DISABLE_ENV_VARS:
                str_value = str(env_value).lower().strip()
                if str_value in _DISABLE_VALUES:
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
                                f"Environment variable '{env_key}' disables "
                                f"TLS certificate validation for server "
                                f"'{snapshot.server_name}'."
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
                        f"No certificate validation bypass detected for "
                        f"server '{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
