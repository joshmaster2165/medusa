"""SSRF-010: Missing URL Scheme Validation.

Detects URL-type parameters that have no scheme-constraining pattern (e.g.,
no `^https?://` pattern), allowing dangerous non-HTTP protocols to be submitted.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.ssrf import URL_PARAM_NAMES

# Pattern indicating a scheme constraint is present
_SCHEME_PATTERN = re.compile(r"\^https?", re.IGNORECASE)


class MissingUrlSchemeValidationCheck(BaseCheck):
    """Detect URL parameters lacking scheme validation constraints."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema") or {}
            properties = (
                input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
            )

            url_params = [p for p in properties if p.lower() in URL_PARAM_NAMES]
            if not url_params:
                continue

            unvalidated: list[str] = []
            for param in url_params:
                param_def = properties.get(param) or {}
                if not isinstance(param_def, dict):
                    continue
                pattern = param_def.get("pattern", "")
                enum_vals = param_def.get("enum", [])
                # PASS if enum restricts to https:// URLs or pattern enforces https?
                if enum_vals and all(
                    str(v).startswith("http://") or str(v).startswith("https://") for v in enum_vals
                ):
                    continue
                if pattern and _SCHEME_PATTERN.search(pattern):
                    continue
                unvalidated.append(param)

            if not unvalidated:
                continue

            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="tool",
                    resource_name=tool_name,
                    status_extended=(
                        f"Tool '{tool_name}' URL parameter(s) {unvalidated} lack "
                        f"scheme validation, allowing file://, gopher://, etc."
                    ),
                    evidence=f"URL params without scheme constraint: {unvalidated}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        if not findings and snapshot.tools:
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
                    status_extended="All URL parameters have scheme validation constraints.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
