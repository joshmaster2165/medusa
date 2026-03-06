"""PMT021: Static Prompt Contains Injection Markers.

Detects MCP prompt definitions that contain hidden instruction tags or injection
phrases. Uses context-aware scoring to reduce false positives from documentation
or security descriptions that mention injection patterns.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import score_injection_context
from medusa.utils.patterns.injection import HIDDEN_TAG_PATTERNS, INJECTION_PHRASES


class StaticPromptInjectionCheck(BaseCheck):
    """Static Prompt Contains Injection Markers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.prompts:
            return findings

        all_patterns = HIDDEN_TAG_PATTERNS + INJECTION_PHRASES

        for prompt in snapshot.prompts:
            prompt_name = prompt.get("name", "<unnamed>")
            prompt_desc = prompt.get("description", "")

            if not prompt_desc:
                continue

            for pattern in all_patterns:
                match = pattern.search(prompt_desc)
                if match:
                    score = score_injection_context(prompt_desc, match.start(), match.end())
                    if score >= 0.5:
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
                                    f"Prompt '{prompt_name}' contains injection "
                                    f"marker matching pattern. Score: {score}. "
                                    f"This could indicate embedded hidden "
                                    f"instructions or prompt injection."
                                ),
                                evidence=(f"matched_text={match.group()[:100]}, score={score}"),
                                remediation=meta.remediation,
                                owasp_mcp=meta.owasp_mcp,
                            )
                        )
                        break  # One finding per prompt is enough

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
                        f"No injection markers found in {len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
