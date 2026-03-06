"""SC-015: Remote Resource Fetch Enabled by Default.

Detects tools that fetch remote content (HTTP/URLs) without
allowlist/blocklist parameters to restrict which domains can be accessed.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.schema import ALLOWLIST_PARAMS

_FETCH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b(fetch|download|get[-_]?url|http[-_]?get|request|scrape|crawl)\b", re.IGNORECASE
    ),
    re.compile(r"\b(web[-_]?fetch|url[-_]?fetch|remote[-_]?get|pull[-_]?url)\b", re.IGNORECASE),
    re.compile(r"\bfetch(es|ed|ing)?\s+(data|content|page|resource|url)", re.IGNORECASE),
    re.compile(r"\bdownload(s|ed|ing)?\s+(file|content|data|resource)", re.IGNORECASE),
    re.compile(r"\bretrieve(s|d)?\s+(from|remote|url|http)", re.IGNORECASE),
]


class RemoteFetchDefaultCheck(BaseCheck):
    """Detect remote fetch tools without domain restrictions."""

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
            tool_name = tool.get("name", "<unnamed>")
            description = tool.get("description", "")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {})
            param_names_lower = {p.lower() for p in properties}

            combined = f"{tool_name} {description}"
            is_fetch_tool = any(p.search(combined) for p in _FETCH_PATTERNS)

            if not is_fetch_tool:
                continue

            has_allowlist = bool(param_names_lower & ALLOWLIST_PARAMS)

            if not has_allowlist:
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
                            f"Tool '{tool_name}' fetches remote content but has no "
                            f"allowlist or blocklist parameter to restrict accessible "
                            f"domains. This allows unrestricted SSRF and data retrieval "
                            f"from any URL including internal services."
                        ),
                        evidence=f"fetch_tool={tool_name}, domain_filter_params=none",
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
                        f"No unrestricted remote fetch tools found across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
