"""RES020: Resource Dependency Chain Risk.

Detects MCP resources that form dependency chains where one resource references or includes
another, creating potential for circular dependencies, infinite resolution loops, and cascading
access control bypasses through transitive resource references.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class ResourceDependencyChainCheck(BaseCheck):
    """Resource Dependency Chain Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.resources:
            return findings

        # Collect all resource URIs
        uri_map: dict[str, str] = {}
        for res in snapshot.resources:
            name = res.get("name", "<unnamed>")
            uri = res.get("uri") or ""
            if uri:
                uri_map[name] = uri

        if not uri_map:
            return findings

        # Check for cross-references: does resource A's URI appear in resource B's URI?
        for name_a, uri_a in uri_map.items():
            # Self-reference check
            for name_b, uri_b in uri_map.items():
                if name_a == name_b:
                    continue
                if uri_a in uri_b or uri_b in uri_a:
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="resource",
                            resource_name=name_a,
                            status_extended=(
                                f"Resource '{name_a}' and '{name_b}' form a dependency "
                                f"chain via overlapping URIs."
                            ),
                            evidence=f"uri_a={uri_a}, uri_b={uri_b}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # Deduplicate bidirectional pairs
        seen: set[tuple[str, str]] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = tuple(sorted([f.resource_name, f.evidence]))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        findings = deduped

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
                    status_extended=(
                        f"No resource dependency chains detected across "
                        f"{len(snapshot.resources)} resource(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
