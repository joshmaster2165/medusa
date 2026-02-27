"""IV032: URL Parameter Injection.

Detects URL-type tool parameters without scheme restrictions. Parameters accepting arbitrary
URLs can be set to file://, javascript:, data:, or internal network URLs, enabling local file
access, script execution, and server-side request forgery.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.schema import URL_PARAM_NAMES


class UrlParameterInjectionCheck(BaseCheck):
    """URL Parameter Injection."""

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
            tool_name: str = tool.get("name", "<unnamed>")
            input_schema: dict | None = tool.get("inputSchema")

            if not input_schema or not isinstance(input_schema, dict):
                continue

            properties: dict = input_schema.get("properties", {})
            if not isinstance(properties, dict):
                continue

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue

                if param_name.lower().strip() not in URL_PARAM_NAMES:
                    continue

                has_format_uri = param_def.get("format") in ("uri", "url", "iri")
                has_pattern = bool(param_def.get("pattern"))
                has_enum = bool(param_def.get("enum"))

                if has_format_uri or has_pattern or has_enum:
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
                        resource_name=f"{tool_name}.{param_name}",
                        status_extended=(
                            f"Tool '{tool_name}' URL parameter '{param_name}' lacks "
                            f"format:uri or pattern constraint. "
                            f"Arbitrary URLs enable file://, javascript:, and SSRF attacks."
                        ),
                        evidence=(
                            f"param={param_name}, type={param_def.get('type', 'N/A')}, "
                            f"format={param_def.get('format', 'N/A')}, "
                            f"pattern={param_def.get('pattern', 'N/A')}"
                        ),
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
                    status_extended=(
                        f"All URL parameters have format:uri or pattern constraints "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
