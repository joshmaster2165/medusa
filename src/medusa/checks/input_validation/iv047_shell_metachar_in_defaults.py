"""IV047: Shell Metacharacters in Parameter Default Values.

Detects parameters whose default values contain shell injection vectors
such as pipes, semicolons, command substitution, or redirects. These
defaults can execute arbitrary commands when the parameter value flows
into a shell context.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SHELL_VECTORS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\|(?!\|)"), "pipe"),
    (re.compile(r";"), "semicolon"),
    (re.compile(r"&&"), "and_chain"),
    (re.compile(r"\|\|"), "or_chain"),
    (re.compile(r"\$\("), "command_sub"),
    (re.compile(r"`[^`]+`"), "backtick_sub"),
    (re.compile(r">>"), "append_redirect"),
    (re.compile(r">(?!>)"), "redirect"),
    (re.compile(r"<(?!<)"), "input_redirect"),
    (re.compile(r"&\s*$"), "background"),
]


class ShellMetacharInDefaultsCheck(BaseCheck):
    """Shell Metacharacters in Parameter Default Values."""

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
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue
                default = param_def.get("default")
                if not isinstance(default, str) or len(default) < 2:
                    continue

                matched: list[str] = []
                for pattern, label in _SHELL_VECTORS:
                    if pattern.search(default):
                        matched.append(label)

                if matched:
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
                                f"Parameter '{param_name}' of tool "
                                f"'{tool_name}' has a default value "
                                f"containing shell metacharacters: "
                                f"{', '.join(matched)}."
                            ),
                            evidence=(f"default={default[:80]}, vectors={matched}"),
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
                        f"No shell metacharacters in default values "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
