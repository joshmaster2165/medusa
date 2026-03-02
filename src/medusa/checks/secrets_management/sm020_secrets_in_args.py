"""SM020: Secrets in Command-Line Arguments.

Detects potential secrets passed via command-line arguments to the MCP
server process. Command-line arguments are visible in process listings,
shell history, and system logs.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import is_likely_secret

# CLI flags that pass credential values.
_SECRET_FLAGS_RE = re.compile(
    r"^--(?:password|token|secret|api[_-]?key|apikey)=(.+)$",
    re.IGNORECASE,
)

# Known secret prefixes (case-sensitive).
_SECRET_PREFIXES: list[str] = [
    "sk-",
    "pk_live_",
    "pk_test_",
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


class SecretsInArgsCheck(BaseCheck):
    """Secrets in Command-Line Arguments."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # Only applicable to stdio transport (command-line based)
        if snapshot.transport_type != "stdio":
            return findings

        if not snapshot.args:
            return findings

        for i, arg in enumerate(snapshot.args):
            # Check for --password=value, --token=value, etc.
            flag_match = _SECRET_FLAGS_RE.match(arg)
            if flag_match:
                value = flag_match.group(1)
                masked = value[:4] + "*" * max(0, len(value) - 4) if len(value) > 4 else "****"
                findings.append(Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Command-line argument at position {i} passes a credential "
                        f"via a flag (e.g., --password=, --token=)."
                    ),
                    evidence=f"Arg[{i}]: {arg.split('=')[0]}={masked}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                ))
                continue

            # Check for known secret prefix patterns
            for prefix in _SECRET_PREFIXES:
                if arg.startswith(prefix) and len(arg) > len(prefix) + 4:
                    masked = arg[:len(prefix) + 4] + "*" * (len(arg) - len(prefix) - 4)
                    findings.append(Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="server",
                        resource_name=snapshot.server_name,
                        status_extended=(
                            f"Command-line argument at position {i} matches known "
                            f"secret prefix '{prefix}'."
                        ),
                        evidence=f"Arg[{i}]: {masked}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    ))
                    break
            else:
                # Check for high-entropy strings (skip short args and flags)
                if not arg.startswith("-") and len(arg) >= 8:
                    is_secret, confidence = is_likely_secret("arg", arg)
                    if is_secret and confidence >= 0.6:
                        masked = arg[:4] + "*" * (len(arg) - 4)
                        findings.append(Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="server",
                            resource_name=snapshot.server_name,
                            status_extended=(
                                f"Command-line argument at position {i} has high entropy "
                                f"(confidence: {confidence:.0%}), suggesting a potential secret."
                            ),
                            evidence=f"Arg[{i}]: {masked}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        ))

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
                status_extended="No secrets detected in command-line arguments.",
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))
        return findings
