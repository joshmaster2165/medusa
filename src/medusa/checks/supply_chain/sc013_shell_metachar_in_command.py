"""SC013: Shell Metacharacters in Server Command.

Detects shell metacharacters in the MCP server command or its arguments,
such as pipes (|), semicolons (;), command chaining (&&, ||), subshell
execution ($(), backticks), and redirections (>, >>, <). These characters
suggest the command may be processed by a shell, enabling injection attacks.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Shell metacharacter patterns with human-readable labels.
_SHELL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\|(?!\|)"), "pipe (|)"),
    (re.compile(r";"), "semicolon (;)"),
    (re.compile(r"&&"), "AND chain (&&)"),
    (re.compile(r"\|\|"), "OR chain (||)"),
    (re.compile(r"\$\("), "command substitution $()"),
    (re.compile(r"`"), "backtick command substitution"),
    (re.compile(r">>"), "append redirect (>>)"),
    (re.compile(r">(?!>)"), "output redirect (>)"),
    (re.compile(r"<"), "input redirect (<)"),
]


def _scan_for_metacharacters(text: str) -> list[str]:
    """Scan text for shell metacharacters.

    Returns a list of human-readable labels for each found pattern.
    """
    found: list[str] = []
    for pattern, label in _SHELL_PATTERNS:
        if pattern.search(text):
            found.append(label)
    return found


class ShellMetacharInCommandCheck(BaseCheck):
    """Shell Metacharacters in Server Command."""

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

        # Check the command itself.
        if snapshot.command:
            cmd_metacharacters = _scan_for_metacharacters(snapshot.command)
            if cmd_metacharacters:
                display_cmd = snapshot.command[:200] + (
                    "..." if len(snapshot.command) > 200 else ""
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
                            f"Server '{snapshot.server_name}' "
                            f"command contains shell "
                            f"metacharacter(s): "
                            f"{', '.join(cmd_metacharacters)}. "
                            f"This may enable command injection "
                            f"or unintended shell execution."
                        ),
                        evidence=(
                            f"location=command, "
                            f"metacharacters="
                            f"{cmd_metacharacters}, "
                            f"command={display_cmd}"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Check each argument.
        for idx, arg in enumerate(snapshot.args):
            arg_metacharacters = _scan_for_metacharacters(arg)
            if arg_metacharacters:
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
                            f"Server '{snapshot.server_name}' "
                            f"argument at index {idx} contains "
                            f"shell metacharacter(s): "
                            f"{', '.join(arg_metacharacters)}. "
                            f"This may enable command injection."
                        ),
                        evidence=(
                            f"location=arg[{idx}], "
                            f"metacharacters="
                            f"{arg_metacharacters}, "
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
                        f"No shell metacharacters detected in "
                        f"command or arguments for "
                        f"'{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
