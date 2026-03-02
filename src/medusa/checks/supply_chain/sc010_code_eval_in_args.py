"""SC010: Code Evaluation in Server Args.

Detects server arguments that contain eval(), exec(), or similar dynamic code
execution patterns. These constructs allow arbitrary code execution and are a
strong indicator of malicious or dangerously misconfigured MCP server launches.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Patterns that indicate dynamic code execution in arguments.
_EVAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\beval\s*\(", re.IGNORECASE), "eval()"),
    (re.compile(r"\bexec\s*\(", re.IGNORECASE), "exec()"),
    (re.compile(r"\b__import__\s*\(", re.IGNORECASE), "__import__()"),
    (re.compile(r"\bcompile\s*\(", re.IGNORECASE), "compile()"),
    (re.compile(r"\bFunction\s*\(", re.IGNORECASE), "Function()"),
    (re.compile(r"\bsetTimeout\s*\(", re.IGNORECASE), "setTimeout()"),
    (re.compile(r"\bsetInterval\s*\(", re.IGNORECASE), "setInterval()"),
    (re.compile(r"\bchild_process\b", re.IGNORECASE), "child_process"),
    (re.compile(r"\bsubprocess\b", re.IGNORECASE), "subprocess"),
    (re.compile(r"\bos\.system\s*\(", re.IGNORECASE), "os.system()"),
]


class CodeEvalInArgsCheck(BaseCheck):
    """Code Evaluation in Server Args."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # Only applicable to stdio transport.
        if snapshot.transport_type != "stdio":
            return findings

        if not snapshot.args:
            return findings

        # Join all args into a single string for comprehensive scanning,
        # but also track which arg index contained the match.
        for idx, arg in enumerate(snapshot.args):
            matched_constructs: list[str] = []
            for pattern, label in _EVAL_PATTERNS:
                if pattern.search(arg):
                    matched_constructs.append(label)

            if matched_constructs:
                # Truncate the arg for display if very long.
                display_arg = arg[:200] + ("..." if len(arg) > 200 else "")
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
                            f"Server '{snapshot.server_name}' argument at index {idx} "
                            f"contains dynamic code execution construct(s): "
                            f"{', '.join(matched_constructs)}. This allows arbitrary "
                            f"code execution during server startup."
                        ),
                        evidence=(
                            f"arg_index={idx}, "
                            f"constructs={matched_constructs}, "
                            f"arg={display_arg}"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings:
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
                        f"No dynamic code execution patterns detected in "
                        f"server arguments for '{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
