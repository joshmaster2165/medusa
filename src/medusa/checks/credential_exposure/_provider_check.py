"""Shared helper for provider-specific credential exposure checks (Pattern D)."""

from __future__ import annotations

import re

from medusa.checks.credential_exposure.cred001_secrets_in_config import (
    _flatten_config,
    _redact,
)
from medusa.core.check import ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


def run_provider_check(
    snapshot: ServerSnapshot,
    meta: CheckMetadata,
    patterns: list[tuple[str, re.Pattern[str]]],
    provider_label: str,
) -> list[Finding]:
    """Execute a provider-specific credential scan and return findings."""
    findings: list[Finding] = []

    scan_targets: list[tuple[str, str]] = []
    if snapshot.config_raw:
        for key, value in _flatten_config(snapshot.config_raw):
            # Also scan "LEAF_KEY=value" so patterns matching key names fire.
            leaf_key = key.split(".")[-1].split("[")[0]
            composite = f"{leaf_key}={value}"
            scan_targets.append((key, composite))
    for i, arg in enumerate(snapshot.args):
        scan_targets.append((f"args[{i}]", arg))
    for env_key, env_value in snapshot.env.items():
        # Scan "KEY=value" composite so patterns that match env var *names*
        # (e.g. JWT_SECRET, SMTP_PASSWORD) still fire.
        composite = f"{env_key}={env_value}"
        scan_targets.append((f"env.{env_key}", composite))

    seen: set[tuple[str, str]] = set()
    for location, value in scan_targets:
        for pattern_name, pattern in patterns:
            for match in pattern.finditer(value):
                dedup_key = (location, pattern_name)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="config",
                        resource_name=location,
                        status_extended=(
                            f"{provider_label} credential pattern '{pattern_name}' "
                            f"detected at '{location}' for server '{snapshot.server_name}'."
                        ),
                        evidence=f"{pattern_name}: {_redact(match.group())}",
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
                resource_type="config",
                resource_name=snapshot.config_file_path or "config",
                status_extended=(
                    f"No {provider_label} credentials detected for server '{snapshot.server_name}'."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        )
    return findings
