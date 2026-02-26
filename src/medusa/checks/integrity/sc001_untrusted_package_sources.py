"""SC-001: Untrusted Package Sources.

Detects MCP server configurations that install packages from non-standard
registries, raw URLs, or unpinned git repositories.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Trusted registries.
_TRUSTED_REGISTRIES: set[str] = {
    "registry.npmjs.org",
    "pypi.org",
}

# Detect --registry flag.
_REGISTRY_FLAG: re.Pattern[str] = re.compile(r"^--registry[=\s]?(.+)$")

# Detect URL-based pip installs.
_URL_PATTERN: re.Pattern[str] = re.compile(r"^https?://", re.IGNORECASE)

# Detect git URLs without commit hash pinning.
_GIT_URL_PATTERN: re.Pattern[str] = re.compile(
    r"(git\+https?://|git://|github:|github\.com/)", re.IGNORECASE
)
_COMMIT_HASH_PIN: re.Pattern[str] = re.compile(r"#[0-9a-f]{7,40}$", re.IGNORECASE)

# Commands that install packages.
_PIP_COMMANDS: set[str] = {"pip", "pip3"}
_NPM_COMMANDS: set[str] = {"npm", "npx", "yarn", "pnpm"}


class UntrustedPackageSourcesCheck(BaseCheck):
    """Check for packages installed from untrusted sources."""

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
        all_args = snapshot.args

        # --- Check for custom registries ---
        for i, arg in enumerate(all_args):
            if arg == "--registry" and i + 1 < len(all_args):
                registry_url = all_args[i + 1]
                if not any(trusted in registry_url for trusted in _TRUSTED_REGISTRIES):
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
                                f"Server '{snapshot.server_name}' uses a custom "
                                f"registry '{registry_url}' that is not a "
                                f"trusted source."
                            ),
                            evidence=f"--registry {registry_url}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )
            elif arg.startswith("--registry="):
                registry_url = arg.split("=", 1)[1]
                if not any(trusted in registry_url for trusted in _TRUSTED_REGISTRIES):
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
                                f"Server '{snapshot.server_name}' uses a custom "
                                f"registry '{registry_url}' that is not a "
                                f"trusted source."
                            ),
                            evidence=f"--registry={registry_url}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # --- Check for pip install from URLs ---
        if command_base in _PIP_COMMANDS:
            in_install = False
            for arg in all_args:
                if arg == "install":
                    in_install = True
                    continue
                if in_install and not arg.startswith("-") and _URL_PATTERN.match(arg):
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
                                f"Server '{snapshot.server_name}' installs a "
                                f"pip package from a URL '{arg}' instead of "
                                f"the official PyPI registry."
                            ),
                            evidence=f"pip install {arg}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # --- Check for npm/yarn install from unpinned git URLs ---
        if command_base in _NPM_COMMANDS:
            in_install = False
            for arg in all_args:
                if arg == "install" or arg == "add":
                    in_install = True
                    continue
                if in_install and not arg.startswith("-") and _GIT_URL_PATTERN.search(arg):
                    if not _COMMIT_HASH_PIN.search(arg):
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
                                    f"Server '{snapshot.server_name}' installs "
                                    f"an npm package from a git URL '{arg}' "
                                    f"without commit hash pinning."
                                ),
                                evidence=f"npm install {arg}",
                                remediation=meta.remediation,
                                owasp_mcp=meta.owasp_mcp,
                            )
                        )

        # Emit PASS if check was applicable and no issues found.
        if not findings and command_base in (_PIP_COMMANDS | _NPM_COMMANDS):
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
                        f"Server '{snapshot.server_name}' uses trusted "
                        f"package sources."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
