"""SAMP-001: Sampling Request Injection.

Checks if sampling config allows arbitrary model prompts without
validation. Fails when sampling is enabled but no content filtering
or validation config is detected.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

SAMPLING_VALIDATION_KEYS: set[str] = {
    "content_filter",
    "input_validation",
    "prompt_validation",
    "sampling_validation",
    "sanitize",
    "sanitization",
    "prompt_filter",
}


class SamplingInjectionCheck(BaseCheck):
    """Sampling Request Injection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if "sampling" not in snapshot.capabilities:
            return findings

        has_validation = _walk_config_for_keys(snapshot.config_raw, SAMPLING_VALIDATION_KEYS)

        if not has_validation:
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
                        "Sampling is enabled but no prompt validation or content "
                        "filtering config detected — arbitrary prompts may be injected."
                    ),
                    evidence="sampling in capabilities; no validation config found.",
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
                    status_extended="Sampling prompt validation or content filtering detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings


def _walk_config_for_keys(config: Any, keys: set[str], _depth: int = 0) -> bool:
    if _depth > 10:
        return False
    if isinstance(config, dict):
        for key in config:
            if isinstance(key, str) and key.lower() in keys:
                return True
            if _walk_config_for_keys(config[key], keys, _depth + 1):
                return True
    elif isinstance(config, list):
        for item in config:
            if _walk_config_for_keys(item, keys, _depth + 1):
                return True
    return False
