"""TP032: Dangerous Default Parameter Values.

Detects parameter defaults containing dangerous content: external URLs,
path traversal sequences, shell metacharacters, or high-entropy strings
that may be secrets. These defaults take effect silently when the LLM
omits a value, enabling parameter manipulation attacks.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import is_likely_secret

_EXTERNAL_URL_RE = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])", re.IGNORECASE
)
_PATH_TRAVERSAL_RE = re.compile(r"\.\.[/\\]")
_SHELL_META_RE = re.compile(r"[|;&`]|\$\(|>>|<<|\|\||\&\&")


def _check_default(param_name: str, value: object) -> list[str]:
    """Return list of issue labels if the default value is dangerous."""
    if not isinstance(value, str) or len(value) < 2:
        return []
    issues: list[str] = []
    if _EXTERNAL_URL_RE.search(value):
        issues.append("external_url")
    if _PATH_TRAVERSAL_RE.search(value):
        issues.append("path_traversal")
    if _SHELL_META_RE.search(value):
        issues.append("shell_metachar")
    is_secret, confidence = is_likely_secret(param_name, value)
    if is_secret and confidence >= 0.6:
        issues.append("possible_secret")
    return issues


class DangerousDefaultValuesCheck(BaseCheck):
    """Dangerous Default Parameter Values."""

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
                if "default" not in param_def:
                    continue
                issues = _check_default(param_name, param_def["default"])
                if issues:
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
                                f"Parameter '{param_name}' of tool '{tool_name}' "
                                f"has a dangerous default value: "
                                f"{', '.join(issues)}."
                            ),
                            evidence=(f"default={str(param_def['default'])[:80]}, issues={issues}"),
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
                        f"No dangerous default values detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
