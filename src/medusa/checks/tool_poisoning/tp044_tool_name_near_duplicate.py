"""TP044: Near-Duplicate Tool Names via Typosquatting.

Detects pairs of tools on the same server whose names are suspiciously similar
(Levenshtein distance 1-2 characters), suggesting potential typosquatting
attacks as described in the Tool Name Conflict TTP.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


class ToolNameNearDuplicateCheck(BaseCheck):
    """Near-Duplicate Tool Names via Typosquatting."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        tool_names = [t.get("name", "") for t in snapshot.tools]
        flagged_pairs: set[tuple[str, str]] = set()

        for i in range(len(tool_names)):
            for j in range(i + 1, len(tool_names)):
                name_a = tool_names[i]
                name_b = tool_names[j]
                lower_a = name_a.lower()
                lower_b = name_b.lower()

                # Skip exact duplicates (handled by tp003)
                if lower_a == lower_b:
                    continue

                # Only compare names of sufficient length
                if len(lower_a) < 5 or len(lower_b) < 5:
                    continue

                # Normalize pair for deduplication
                pair_key = (lower_a, lower_b) if lower_a < lower_b else (lower_b, lower_a)
                if pair_key in flagged_pairs:
                    continue

                dist = _levenshtein(lower_a, lower_b)
                if 1 <= dist <= 2:
                    flagged_pairs.add(pair_key)
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="tool",
                            resource_name=name_a,
                            status_extended=(
                                f"Tools '{name_a}' and '{name_b}' have "
                                f"suspiciously similar names "
                                f"(distance={dist}). This may indicate "
                                f"a typosquatting attack."
                            ),
                            evidence=(f"pair=[{name_a}, {name_b}], levenshtein_distance={dist}"),
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        if not findings and snapshot.tools:
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
                        f"No near-duplicate tool names detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
