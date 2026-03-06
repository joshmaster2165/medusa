"""TP-057: Description-Schema Capability Mismatch.

Detects tools where the description claims limited scope but the schema
contradicts it across three mismatch categories:

1. **Read-only/safe/view claim + write/delete/execute/network params** --
   description says "read-only", "safe read", "view", "no write" but schema
   has write, delete, execute, or network-oriented parameters.

2. **Local/offline claim + network params** -- description says "local only",
   "local file", "offline", "no network/internet/external", "does not connect"
   but schema has parameters named url, uri, endpoint, webhook, callback,
   callback_url, host, domain, http_url, api_url, fetch_url, remote.

3. **Non-destructive/safe claim + destructive params** -- description says
   "non-destructive", "safe", "no side-effect/data-loss/deletion", "reversible"
   but schema has parameters named delete, drop, remove, wipe, purge, destroy,
   truncate, erase, force_delete, hard_delete.

Extends TP-051 (read-only vs write) to cover more deception patterns.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# ---------------------------------------------------------------------------
# Category 1: "Read-only / safe / view" claim + write/delete/execute params
# (carried over from TP-051 scope for completeness)
# ---------------------------------------------------------------------------
_READONLY_CLAIMS: list[re.Pattern[str]] = [
    re.compile(r"\bread[-\s]?only\b", re.IGNORECASE),
    re.compile(r"\bsafe(ly)?\s+(read|view|inspect|browse)\b", re.IGNORECASE),
    re.compile(r"\bno\s+(write|modify|delete|change|side.?effect)\b", re.IGNORECASE),
    re.compile(r"\bdoes\s+not\s+(modify|write|delete|change)\b", re.IGNORECASE),
]

_WRITE_PARAM_NAMES: set[str] = {
    "write",
    "delete",
    "remove",
    "execute",
    "command",
    "shell",
    "modify",
    "update",
    "overwrite",
    "create",
    "drop",
    "truncate",
    "destroy",
    "kill",
    "exec",
    "run",
    "script",
    "bash",
    "purge",
    "wipe",
}

# ---------------------------------------------------------------------------
# Category 2: "Local / offline / no-network" claim + network params
# ---------------------------------------------------------------------------
_LOCAL_CLAIMS: list[re.Pattern[str]] = [
    re.compile(r"\blocal\s+(only|file|disk)\b", re.IGNORECASE),
    re.compile(r"\boffline\b", re.IGNORECASE),
    re.compile(r"\bno\s+(network|internet|external)\b", re.IGNORECASE),
    re.compile(r"\bdoes\s+not\s+(connect|call|fetch|request)\b", re.IGNORECASE),
]

_NETWORK_PARAM_NAMES: set[str] = {
    "url",
    "uri",
    "endpoint",
    "webhook",
    "callback",
    "callback_url",
    "host",
    "domain",
    "http_url",
    "api_url",
    "fetch_url",
    "remote",
}

# ---------------------------------------------------------------------------
# Category 3: "Non-destructive / safe / reversible" claim + destructive params
# ---------------------------------------------------------------------------
_SAFE_CLAIMS: list[re.Pattern[str]] = [
    re.compile(r"\bnon[-\s]?destructive\b", re.IGNORECASE),
    re.compile(r"\bsafe\b", re.IGNORECASE),
    re.compile(r"\bno\s+(side.?effect|data.?loss|deletion)\b", re.IGNORECASE),
    re.compile(r"\breversible\b", re.IGNORECASE),
]

_DESTRUCTIVE_PARAM_NAMES: set[str] = {
    "delete",
    "drop",
    "remove",
    "wipe",
    "purge",
    "destroy",
    "truncate",
    "erase",
    "force_delete",
    "hard_delete",
}

# ---------------------------------------------------------------------------
# Unified category definitions
# ---------------------------------------------------------------------------
_CATEGORIES: list[tuple[str, list[re.Pattern[str]], set[str], str]] = [
    (
        "read-only/safe claim + write/execute params",
        _READONLY_CLAIMS,
        _WRITE_PARAM_NAMES,
        "claims read-only/safe behavior but has write/delete/execute parameters",
    ),
    (
        "local/offline claim + network params",
        _LOCAL_CLAIMS,
        _NETWORK_PARAM_NAMES,
        "claims local/offline behavior but has network-oriented parameters",
    ),
    (
        "non-destructive claim + destructive params",
        _SAFE_CLAIMS,
        _DESTRUCTIVE_PARAM_NAMES,
        "claims non-destructive/safe behavior but has destructive parameters",
    ),
]


class DescriptionSchemaMismatchCheck(BaseCheck):
    """Detect description-schema capability mismatches across 3 categories."""

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
            param_names_lower = {k.lower() for k in properties}

            for (
                category_label,
                claim_patterns,
                dangerous_params,
                mismatch_msg,
            ) in _CATEGORIES:
                # Check for claim in description
                has_claim = any(p.search(description) for p in claim_patterns)
                if not has_claim:
                    continue

                # Check for contradicting params
                conflicting = param_names_lower & dangerous_params
                if not conflicting:
                    continue

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
                            f"Tool '{tool_name}' {mismatch_msg}: "
                            f"{', '.join(sorted(conflicting))}. "
                            f"This misrepresents the tool's actual "
                            f"capabilities."
                        ),
                        evidence=(
                            f"category={category_label}, "
                            f"claim_matched=True, "
                            f"conflicting_params={sorted(conflicting)}"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Emit a PASS if tools were scanned but no issues were found
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
                        f"No description-schema capability mismatches "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
