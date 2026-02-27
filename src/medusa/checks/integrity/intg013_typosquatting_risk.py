"""INTG013: Typosquatting Risk.

Detects MCP server dependencies with package names suspiciously similar to popular packages.
Typosquatting attacks register malicious packages with names that are common misspellings of
popular packages.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_POPULAR_PACKAGES = {
    "express",
    "lodash",
    "react",
    "axios",
    "chalk",
    "commander",
    "webpack",
    "typescript",
    "eslint",
    "prettier",
    "next",
    "vue",
    "angular",
    "jquery",
    "moment",
    "uuid",
    "dotenv",
    "cors",
    "body-parser",
    "mongoose",
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "tensorflow",
    "pytorch",
}

_PKG_PATTERN = re.compile(r"(?:@[\w-]+/)?([\w][-\w.]*)")


def _is_typosquat(name: str, popular: set[str]) -> str | None:
    clean = name.lower().strip()
    if clean in popular:
        return None
    for pkg in popular:
        if len(clean) < 3 or len(pkg) < 3:
            continue
        if abs(len(clean) - len(pkg)) > 2:
            continue
        diffs = sum(1 for a, b in zip(clean, pkg) if a != b)
        if len(clean) == len(pkg) and diffs == 1:
            return pkg
        if clean.replace("-", "") == pkg.replace("-", ""):
            return pkg
        if clean.replace("_", "-") == pkg or pkg.replace("_", "-") == clean:
            return pkg
    return None


class TyposquattingRiskCheck(BaseCheck):
    """Typosquatting Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if snapshot.transport_type != "stdio" or not snapshot.command:
            return findings

        for arg in snapshot.args:
            m = _PKG_PATTERN.match(arg)
            if not m:
                continue
            pkg_name = m.group(1)
            similar = _is_typosquat(pkg_name, _POPULAR_PACKAGES)
            if similar:
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
                        status_extended=f"Package '{pkg_name}' is suspiciously similar to"
                        f"popular package '{similar}'.",
                        evidence=f"package={pkg_name}, similar_to={similar}",
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
                    status_extended="No typosquatting risks detected in package references.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
