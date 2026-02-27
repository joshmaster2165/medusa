"""SAMP-002: Model Manipulation via Sampling.

Checks for model selection override in sampling config. Fails if sampling
is enabled and model preferences can be overridden without restrictions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

MODEL_RESTRICTION_KEYS: set[str] = {
    "allowed_models",
    "model_allowlist",
    "model_whitelist",
    "permitted_models",
    "model_restriction",
    "locked_model",
    "fixed_model",
}

MODEL_OVERRIDE_KEYS: set[str] = {
    "model_override",
    "override_model",
    "model_preference",
    "allow_model_selection",
    "dynamic_model",
}


class ModelManipulationViaSamplingCheck(BaseCheck):
    """Model Manipulation via Sampling."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if "sampling" not in snapshot.capabilities:
            return findings

        has_restriction = _walk_config_for_keys(snapshot.config_raw, MODEL_RESTRICTION_KEYS)
        has_override = _walk_config_for_keys(snapshot.config_raw, MODEL_OVERRIDE_KEYS)

        if has_override and not has_restriction:
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
                        "Sampling has model override capability without a model allowlist — "
                        "model selection can be manipulated."
                    ),
                    evidence="model_override config present; no model restriction found.",
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
                    status_extended="No unrestricted model manipulation via sampling detected.",
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
