"""SM008: Insecure Secret Generation.

Detects MCP servers that generate secrets using weak random number generators, predictable
algorithms, or insufficient entropy sources. Weakly generated secrets can be predicted or brute-
forced by attackers who understand the generation algorithm.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Patterns that indicate weak/insecure randomness in config values
_WEAK_SEED_RE = re.compile(
    r"\b(random\.seed|Math\.random|rand\(\)|srand|mt_rand|weak_rand|insecure_random)\b",
    re.IGNORECASE,
)
_WEAK_GEN_KEYS = {
    "random_seed",
    "seed",
    "insecure_random",
    "weak_random",
    "pseudo_random",
}


class InsecureSecretGenerationCheck(BaseCheck):
    """Insecure Secret Generation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        targets: list[tuple[str, str]] = []
        if snapshot.config_raw:
            targets.extend(_flatten_config(snapshot.config_raw))
        for i, arg in enumerate(snapshot.args):
            targets.append((f"args[{i}]", arg))

        for location, value in targets:
            leaf = location.split(".")[-1].split("[")[0].lower()
            if leaf in _WEAK_GEN_KEYS or _WEAK_SEED_RE.search(value):
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="config",
                        resource_name=location,
                        status_extended=(
                            f"Insecure secret generation indicator detected at '{location}' for "
                            f"server '{snapshot.server_name}'."
                        ),
                        evidence=f"{location}: {value[:60]}",
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
                    resource_type="config",
                    resource_name=snapshot.config_file_path or "config",
                    status_extended=(
                        f"No insecure secret generation patterns detected for server "
                        f"'{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        return findings
