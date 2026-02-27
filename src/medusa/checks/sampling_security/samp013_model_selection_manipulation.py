"""SAMP-013: Model Selection Manipulation.

Checks if model selection is restricted. Fails when sampling is enabled
and no model allowlist or selection restriction config is found.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

MODEL_SELECTION_RESTRICTION_KEYS: set[str] = {
    "allowed_models",
    "model_allowlist",
    "model_whitelist",
    "permitted_models",
    "model_restriction",
    "lock_model",
    "fixed_model",
    "enforce_model",
    "approved_models",
}


class ModelSelectionManipulationCheck(BaseCheck):
    """Model Selection Manipulation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if "sampling" not in snapshot.capabilities:
            return findings

        has_restriction = _walk_config_for_keys(
            snapshot.config_raw, MODEL_SELECTION_RESTRICTION_KEYS
        )

        if not has_restriction:
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
                        "Sampling is enabled but no model selection restriction config detected — "
                        "a weaker or unsafe model may be selected to bypass guardrails."
                    ),
                    evidence="sampling in capabilities; no model restriction config.",
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
                    status_extended="Model selection restriction detected.",
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
