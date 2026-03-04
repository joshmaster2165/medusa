"""TP053: Description-Schema Domain Mismatch.

Detects tools where description keywords indicate one domain (e.g., file
operations) but schema parameters indicate a completely different domain
(e.g., network URLs, shell commands). This cross-domain mismatch is a
strong indicator of metadata manipulation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Domain classification based on description keywords
_DESC_DOMAIN_KEYWORDS: dict[str, set[str]] = {
    "file": {
        "file",
        "files",
        "directory",
        "directories",
        "folder",
        "folders",
        "path",
        "filesystem",
        "read file",
        "write file",
        "open file",
        "save file",
        "file system",
    },
    "network": {
        "http",
        "https",
        "api",
        "endpoint",
        "request",
        "response",
        "webhook",
        "url",
        "download",
        "upload",
        "fetch",
        "hostname",
        "dns",
        "socket",
    },
    "database": {
        "database",
        "sql",
        "query",
        "table",
        "schema",
        "record",
        "row",
        "column",
        "collection",
        "document",
        "mongodb",
        "postgres",
        "mysql",
        "sqlite",
    },
    "shell": {
        "command",
        "shell",
        "terminal",
        "bash",
        "execute",
        "process",
        "subprocess",
        "script",
        "cli",
        "run command",
        "exec",
    },
}

# Domain classification based on parameter names
_PARAM_DOMAIN_KEYWORDS: dict[str, set[str]] = {
    "file": {
        "file",
        "filepath",
        "file_path",
        "filename",
        "file_name",
        "directory",
        "dir",
        "folder",
        "path",
        "source",
        "destination",
    },
    "network": {
        "url",
        "uri",
        "endpoint",
        "host",
        "webhook",
        "callback_url",
        "webhook_url",
        "remote_url",
        "target_url",
        "api_url",
    },
    "database": {
        "query",
        "sql",
        "table",
        "schema",
        "collection",
        "database",
        "db_query",
        "raw_query",
        "pipeline",
    },
    "shell": {
        "command",
        "cmd",
        "shell",
        "exec",
        "execute",
        "run",
        "script",
        "bash",
        "sh",
        "subprocess",
    },
}


def _classify_domain(text: str, keywords: dict[str, set[str]]) -> str | None:
    """Classify text into a domain based on keyword frequency."""
    text_lower = text.lower()
    scores: dict[str, int] = {}
    for domain, words in keywords.items():
        score = sum(1 for w in words if w in text_lower)
        if score > 0:
            scores[domain] = score

    if not scores:
        return None

    best = max(scores, key=lambda d: scores[d])
    # Require at least 2 keyword hits to be confident
    if scores[best] < 2:
        return None
    return best


class DescriptionSchemaDomainMismatchCheck(BaseCheck):
    """Description-Schema Domain Mismatch."""

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
            description: str = tool.get("description", "")

            if not description:
                continue

            # Extract parameter names from schema
            schema = tool.get("inputSchema") or tool.get("parameters", {})
            properties = schema.get("properties", {})
            param_text = " ".join(properties.keys())

            desc_domain = _classify_domain(description, _DESC_DOMAIN_KEYWORDS)
            param_domain = _classify_domain(param_text, _PARAM_DOMAIN_KEYWORDS)

            if desc_domain is not None and param_domain is not None and desc_domain != param_domain:
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
                            f"Tool '{tool_name}' description indicates "
                            f"'{desc_domain}' domain but parameters "
                            f"indicate '{param_domain}' domain. This "
                            f"mismatch may indicate metadata "
                            f"manipulation."
                        ),
                        evidence=(
                            f"desc_domain={desc_domain}, "
                            f"param_domain={param_domain}, "
                            f"params={list(properties.keys())[:5]}"
                        ),
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
                        f"No description-schema domain mismatches "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
