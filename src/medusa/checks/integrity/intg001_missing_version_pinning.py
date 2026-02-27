"""INTG-001: Missing Version Pinning for Package Manager Commands.

Detects MCP servers launched via npx -y or uvx without explicit version
pins, exposing the host to supply-chain attacks through auto-installed
latest versions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import VERSION_PIN_PATTERN

# Commands that auto-install packages.
_NPX_COMMANDS = {"npx"}
_UVX_COMMANDS = {"uvx"}


def _has_auto_yes(args: list[str]) -> bool:
    """Return True if the argument list contains npx auto-accept flags."""
    for arg in args:
        if arg in ("-y", "--yes"):
            return True
    return False


def _npx_package_arg(args: list[str]) -> str | None:
    """Return the first positional (non-flag) argument, which is the package name."""
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            # Flags that take a value
            if arg in ("-p", "--package"):
                skip_next = True
            continue
        return arg
    return None


class MissingVersionPinningCheck(BaseCheck):
    """Check for unpinned package versions in auto-install commands."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # Only applicable to stdio transport with a command.
        if snapshot.transport_type != "stdio" or not snapshot.command:
            return findings

        command_base = Path(snapshot.command).name.lower()

        # --- npx check ---
        if command_base in _NPX_COMMANDS:
            if _has_auto_yes(snapshot.args):
                pkg = _npx_package_arg(snapshot.args)
                if pkg and not VERSION_PIN_PATTERN.search(pkg):
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
                                f"Server '{snapshot.server_name}' uses npx with "
                                f"auto-accept (-y/--yes) and package '{pkg}' has "
                                f"no version pin. An attacker could publish a "
                                f"malicious update that runs automatically."
                            ),
                            evidence=f"command=npx, args={snapshot.args}, package={pkg}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # --- uvx check ---
        if command_base in _UVX_COMMANDS:
            pkg = _npx_package_arg(snapshot.args)
            if pkg and not VERSION_PIN_PATTERN.search(pkg):
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
                            f"Server '{snapshot.server_name}' uses uvx with "
                            f"package '{pkg}' and no version pin. An attacker "
                            f"could publish a malicious update that runs "
                            f"automatically."
                        ),
                        evidence=f"command=uvx, args={snapshot.args}, package={pkg}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Emit PASS if the check was applicable but no issues found.
        if not findings and command_base in (_NPX_COMMANDS | _UVX_COMMANDS):
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
                        f"Server '{snapshot.server_name}' has properly pinned package versions."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
