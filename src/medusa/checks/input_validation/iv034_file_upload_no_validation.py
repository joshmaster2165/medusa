"""IV034: File Upload Without Validation.

Detects file upload tool parameters without type, size, or content validation constraints.
Unrestricted file uploads allow attackers to submit malicious executables, oversized files for
denial of service, or files with double extensions to bypass type restrictions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.schema import FILE_PARAM_NAMES


class FileUploadNoValidationCheck(BaseCheck):
    """File Upload Without Validation."""

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

                if param_name.lower().strip() not in FILE_PARAM_NAMES:
                    continue

                # Check for type/size constraints
                has_enum = bool(param_def.get("enum"))
                has_pattern = bool(param_def.get("pattern"))
                has_max_length = "maxLength" in param_def  # proxy for size limit on base64
                has_content_type = bool(param_def.get("contentMediaType"))
                has_format = bool(param_def.get("format"))

                if has_enum or has_pattern or has_max_length or has_content_type or has_format:
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
                            f"Tool '{tool_name}' file upload parameter '{param_name}' has "
                            f"no type, size, or content validation. "
                            f"Unrestricted uploads allow malicious executables and DoS via "
                            f"oversized files."
                        ),
                        evidence=(
                            f"param={param_name}, type={param_def.get('type', 'N/A')}, "
                            f"maxLength=N/A, contentMediaType=N/A, pattern=N/A"
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
                        f"All file upload parameters have type or size constraints "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
