"""TF-003: Environment Variable Exfiltration Flow.

Detects when a server has both environment-reading tools AND external-sending
tools, enabling exfiltration of secrets stored in environment variables.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.tool_classifier import classify_tools

_ENV_READ_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(get|read|list|dump|print|show|echo)[-_]?(env|environment|config|variable|setting)",
        re.IGNORECASE,
    ),
    re.compile(r"(env|environment|config)[-_]?(get|read|list|dump|show|var)", re.IGNORECASE),
    re.compile(r"\becho\b", re.IGNORECASE),
    re.compile(r"(process|system)[-_]?(env|environment)", re.IGNORECASE),
]


class EnvExfilFlowCheck(BaseCheck):
    """Detect environment variable exfiltration flows."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools or len(snapshot.tools) < 2:
            return findings

        labels = classify_tools(snapshot.tools)

        # Identify env-reading tools
        env_readers: set[str] = set()
        for tool in snapshot.tools:
            name = tool.get("name", "")
            desc = tool.get("description", "")
            combined = f"{name} {desc}"
            for pattern in _ENV_READ_PATTERNS:
                if pattern.search(combined):
                    env_readers.add(name)
                    break

        # Identify public sinks
        sinks = {name for name, lbl in labels.items() if lbl.public_sink > 0}

        if env_readers and sinks:
            flow_desc = (
                f"Env readers: {', '.join(sorted(env_readers)[:5])} → "
                f"Public sinks: {', '.join(sorted(sinks)[:5])}"
            )
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
                        f"Server exposes an environment variable exfiltration flow: "
                        f"tools that can read environment variables ({len(env_readers)}) "
                        f"and tools that send data externally ({len(sinks)}) are both "
                        f"present. An attacker could chain these to exfiltrate secrets "
                        f"stored in environment variables (API keys, tokens, passwords)."
                    ),
                    evidence=flow_desc,
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
                    status_extended=(
                        f"No environment variable exfiltration flow detected across "
                        f"{len(snapshot.tools)} tool(s). Server does not expose both "
                        f"environment-reading tools and external output sinks."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
