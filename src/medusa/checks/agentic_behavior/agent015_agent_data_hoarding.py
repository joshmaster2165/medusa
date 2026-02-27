"""AGENT-015: Agent Data Hoarding.

Checks for tools that accumulate or store data (bulk fetch, export, dump,
collect_all) without data retention/quota limits in config.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.rate_limiting_patterns import RESOURCE_LIMIT_KEYS

DATA_HOARD_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(dump|export|extract)[-_]?(all|full|entire|complete)", re.IGNORECASE),
    re.compile(r"(collect|gather|harvest)[-_]?(all|bulk|batch|every)", re.IGNORECASE),
    re.compile(r"(get|fetch|retrieve)[-_]?(all|everything|bulk)", re.IGNORECASE),
    re.compile(r"bulk[-_]?(download|export|copy|collect)", re.IGNORECASE),
    re.compile(r"(aggregate|accumulate)\s+(data|records|logs|files)", re.IGNORECASE),
]


class AgentDataHoardingCheck(BaseCheck):
    """Agent Data Hoarding."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        has_limits = _walk_config_for_keys(snapshot.config_raw, RESOURCE_LIMIT_KEYS)

        hoard_tools: list[str] = []
        for tool in snapshot.tools:
            combined = f"{tool.get('name', '')} {tool.get('description', '')}"
            if any(p.search(combined) for p in DATA_HOARD_PATTERNS):
                hoard_tools.append(tool.get("name", "<unnamed>"))

        if hoard_tools and not has_limits:
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
                        f"Data accumulation tool(s) found "
                        f"({', '.join(hoard_tools[:5])}) without resource limit config."
                    ),
                    evidence=f"hoarding_tools={hoard_tools[:5]}",
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
                    status_extended="No uncontrolled data hoarding tools detected.",
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
