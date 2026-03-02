"""SM017: Secrets in Tool Descriptions.

Detects API keys, tokens, and secrets accidentally exposed in tool
description text. Scans for known secret prefixes and key=value patterns
that indicate credentials have been pasted into documentation strings.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Known secret prefixes (case-sensitive).
_SECRET_PREFIXES: list[str] = [
    "sk-",
    "pk_live_",
    "pk_test_",
    "Bearer ",
    "AKIA",
    "ghp_",
    "gho_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "glpat-",
    "pypi-",
    "npm_",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "sq0atp-",
    "EAACEdEose0cBA",
    "key-",
    "SG.",
    "xkeysib-",
]

# Patterns like password=<value>, token=<value>, etc.
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?:password|token|secret|api_key|apikey)=(\S+)",
    re.IGNORECASE,
)


class SecretsInToolDescriptionsCheck(BaseCheck):
    """Secrets in Tool Descriptions."""

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
            tool_name = tool.get("name", "unknown")
            description = tool.get("description", "")
            if not description:
                continue

            # Check for known secret prefixes (case-sensitive)
            for prefix in _SECRET_PREFIXES:
                idx = description.find(prefix)
                if idx != -1:
                    # Extract a snippet around the match for evidence
                    start = max(0, idx - 10)
                    end = min(len(description), idx + len(prefix) + 20)
                    snippet = description[start:end]
                    findings.append(Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=(
                            f"Tool '{tool_name}' description contains a string matching "
                            f"known secret prefix '{prefix}'."
                        ),
                        evidence=f"Snippet: ...{snippet}...",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    ))
                    break  # One finding per tool for prefix matches

            # Check for credential assignment patterns
            matches = _CREDENTIAL_ASSIGNMENT_RE.findall(description)
            for match_value in matches:
                if len(match_value) >= 6:  # Ignore very short values
                    findings.append(Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=(
                            f"Tool '{tool_name}' description contains a credential "
                            f"assignment pattern with a value of length {len(match_value)}."
                        ),
                        evidence=f"Pattern match: <key>={match_value[:4]}****",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    ))
                    break  # One finding per tool for assignment patterns

        if not findings:
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended="No secrets detected in tool descriptions.",
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))
        return findings
