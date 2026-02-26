"""CRED-001: Secrets in MCP Configuration Files.

Scans the raw MCP configuration (env block, args, and other string values)
for hardcoded secrets using known credential patterns.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import SECRET_PATTERNS


def _redact(value: str, keep: int = 4) -> str:
    """Redact a secret value, keeping only the first few characters."""
    if len(value) <= keep:
        return "***"
    return value[:keep] + "***"


def _scan_string(text: str) -> list[tuple[str, str]]:
    """Scan a string for secret patterns.

    Returns list of (pattern_name, matched_value) tuples.
    """
    hits: list[tuple[str, str]] = []
    for pattern_name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            hits.append((pattern_name, match.group()))
    return hits


def _flatten_config(config: dict, prefix: str = "") -> list[tuple[str, str]]:
    """Flatten a nested config dict into (dotted_key, string_value) pairs."""
    pairs: list[tuple[str, str]] = []
    for key, value in config.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            pairs.extend(_flatten_config(value, full_key))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    pairs.extend(_flatten_config(item, f"{full_key}[{i}]"))
                elif isinstance(item, str):
                    pairs.append((f"{full_key}[{i}]", item))
        elif isinstance(value, str):
            pairs.append((full_key, value))
    return pairs


class SecretsInConfigCheck(BaseCheck):
    """Check for hardcoded secrets in MCP configuration files."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # Collect all string values to scan.
        scan_targets: list[tuple[str, str]] = []

        # 1. Flatten the entire config_raw dict.
        if snapshot.config_raw:
            scan_targets.extend(_flatten_config(snapshot.config_raw))

        # 2. Scan command-line arguments.
        for i, arg in enumerate(snapshot.args):
            scan_targets.append((f"args[{i}]", arg))

        # 3. Scan environment variable values.
        for env_key, env_value in snapshot.env.items():
            scan_targets.append((f"env.{env_key}", env_value))

        # Scan each target for secrets.
        seen: set[tuple[str, str]] = set()  # Deduplicate by (location, pattern).
        for location, value in scan_targets:
            hits = _scan_string(value)
            for pattern_name, matched in hits:
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
                            f"Hardcoded {pattern_name} detected in configuration "
                            f"at '{location}' for server '{snapshot.server_name}'. "
                            f"Secrets in config files can be extracted by anyone "
                            f"with read access."
                        ),
                        evidence=f"{pattern_name}: {_redact(matched)}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # If nothing was found, emit a PASS.
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
                        f"No hardcoded secrets detected in the configuration "
                        f"for server '{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
