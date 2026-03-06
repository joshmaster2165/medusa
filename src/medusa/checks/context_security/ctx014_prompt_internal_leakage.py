"""CTX014: Prompt Leaks Internal Implementation Details.

Detects MCP prompt definitions that expose internal implementation details such
as file paths, SQL statements, database connection strings, internal hostnames,
stack traces, or environment variable references. This information helps attackers
map internal infrastructure.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.context_patterns import INTERNAL_LEAK_PATTERNS


class PromptInternalLeakageCheck(BaseCheck):
    """Prompt Leaks Internal Implementation Details."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.prompts:
            return findings

        for prompt in snapshot.prompts:
            prompt_name = prompt.get("name", "<unnamed>")
            prompt_desc = prompt.get("description", "")

            if not prompt_desc:
                continue

            leaked_types: list[str] = []
            leaked_evidence: list[str] = []
            for label, pattern in INTERNAL_LEAK_PATTERNS:
                match = pattern.search(prompt_desc)
                if match:
                    leaked_types.append(label)
                    leaked_evidence.append(match.group()[:80])

            if leaked_types:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="prompt",
                        resource_name=prompt_name,
                        status_extended=(
                            f"Prompt '{prompt_name}' leaks internal "
                            f"implementation details: "
                            f"{', '.join(leaked_types)}. This information "
                            f"helps attackers map internal infrastructure."
                        ),
                        evidence=(f"leaked_types={leaked_types}, samples={leaked_evidence[:3]}"),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and snapshot.prompts:
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
                        f"No internal implementation leakage found in "
                        f"{len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
