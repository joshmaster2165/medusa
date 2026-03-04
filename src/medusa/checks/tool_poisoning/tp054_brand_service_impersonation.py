"""TP054: Brand/Service Impersonation.

Detects well-known brand or service names in tool names that may indicate
impersonation of established services (e.g., a tool named "google_search"
or "github_api" on an unrelated server).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_KNOWN_BRANDS: set[str] = {
    "google",
    "microsoft",
    "amazon",
    "aws",
    "azure",
    "github",
    "slack",
    "stripe",
    "twilio",
    "openai",
    "anthropic",
    "meta",
    "facebook",
    "apple",
    "dropbox",
    "salesforce",
    "jira",
    "confluence",
    "notion",
    "figma",
    "vercel",
    "netlify",
    "heroku",
    "cloudflare",
    "datadog",
    "splunk",
    "pagerduty",
    "okta",
    "auth0",
    "firebase",
    "supabase",
    "mongodb",
}

_BRAND_PATTERN: re.Pattern[str] = re.compile(
    r"\b(" + "|".join(re.escape(b) for b in sorted(_KNOWN_BRANDS)) + r")\b",
    re.IGNORECASE,
)


class BrandServiceImpersonationCheck(BaseCheck):
    """Brand/Service Impersonation."""

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
            tool_name: str = tool.get("name", "<unnamed>")

            # Normalize: replace hyphens/underscores with spaces for matching
            name_normalized = tool_name.replace("-", " ").replace("_", " ")
            brand_matches = _BRAND_PATTERN.findall(name_normalized)

            if brand_matches:
                unique_brands = sorted(set(b.lower() for b in brand_matches))
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=(
                            f"Tool '{tool_name}' contains brand/service "
                            f"name(s): {', '.join(unique_brands)}. "
                            f"Without verifiable provenance, this may "
                            f"indicate tool impersonation."
                        ),
                        evidence=(f"brands={unique_brands}, tool_name={tool_name}"),
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
                        f"No brand/service impersonation detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
