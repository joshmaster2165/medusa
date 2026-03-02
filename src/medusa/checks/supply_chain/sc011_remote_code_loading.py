"""SC011: Remote Code Loading in Args.

Detects server arguments containing URLs that suggest remote code download and
execution. Patterns like 'curl ... | sh' or 'wget ... && bash' allow an attacker
to serve arbitrary code that executes with the MCP server's privileges.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Severity, Status

# URL pattern: matches http://, https://, ftp:// URLs.
_URL_PATTERN: re.Pattern[str] = re.compile(
    r"(https?://|ftp://)\S+", re.IGNORECASE
)

# Patterns indicating remote code execution when combined with URLs.
_EXEC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\|\s*(?:sh|bash|zsh|dash|ksh)\b", re.IGNORECASE),
    re.compile(r"\bcurl\b.*\|", re.IGNORECASE),
    re.compile(r"\bwget\b.*(?:&&|\|)", re.IGNORECASE),
    re.compile(r"-e\s+['\"]?require\b", re.IGNORECASE),
    re.compile(r"--eval\b", re.IGNORECASE),
    re.compile(r"--require\b", re.IGNORECASE),
    re.compile(r"\bpython\S*\s+-c\b", re.IGNORECASE),
    re.compile(r"\bnode\s+-e\b", re.IGNORECASE),
    re.compile(r"\bruby\s+-e\b", re.IGNORECASE),
    re.compile(r"\bperl\s+-e\b", re.IGNORECASE),
]


class RemoteCodeLoadingCheck(BaseCheck):
    """Remote Code Loading in Args."""

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

        # Join args for pattern matching across argument boundaries.
        full_args = " ".join(snapshot.args)

        # Check for URLs in the arguments.
        urls_found = _URL_PATTERN.findall(full_args)
        if not urls_found:
            # No URLs, emit PASS.
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
                        f"No remote URLs detected in server arguments for "
                        f"'{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        # Check for execution patterns combined with URLs.
        exec_matches: list[str] = []
        for pattern in _EXEC_PATTERNS:
            if pattern.search(full_args):
                exec_matches.append(pattern.pattern)

        if exec_matches:
            # CRITICAL: URL + execution pattern
            display_args = full_args[:300] + ("..." if len(full_args) > 300 else "")
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' arguments contain URL(s) "
                        f"combined with code execution patterns. This indicates "
                        f"remote code download and execution, allowing an attacker "
                        f"to serve arbitrary payloads."
                    ),
                    evidence=(
                        f"urls={urls_found[:3]}, "
                        f"exec_patterns={len(exec_matches)}, "
                        f"args={display_args}"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
            # MEDIUM: URL present but no obvious execution pattern.
            display_args = full_args[:300] + ("..." if len(full_args) > 300 else "")
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' arguments contain URL(s) "
                        f"that may be used for remote resource loading: "
                        f"{', '.join(urls_found[:3])}."
                    ),
                    evidence=(
                        f"urls={urls_found[:3]}, "
                        f"args={display_args}"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
