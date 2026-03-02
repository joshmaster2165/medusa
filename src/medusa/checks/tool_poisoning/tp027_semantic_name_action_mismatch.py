"""TP027: Semantic Name-Action Mismatch.

Detects tools whose names suggest read-only behaviour (get_, read_, list_, fetch_,
search_, view_, show_) but whose descriptions contain destructive or exfiltrative
keywords (delete, remove, send, upload, execute, modify, write, drop, forward,
transmit). This mismatch can trick LLMs into invoking dangerous operations without
appropriate safety confirmations.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk

# Read-only prefixes in tool names.
_READ_ONLY_PREFIXES: tuple[str, ...] = (
    "get_",
    "get-",
    "read_",
    "read-",
    "list_",
    "list-",
    "fetch_",
    "fetch-",
    "search_",
    "search-",
    "view_",
    "view-",
    "show_",
    "show-",
)

# Destructive / exfiltrative keywords in descriptions.
_DANGEROUS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bdelete\b", re.IGNORECASE),
    re.compile(r"\bremove\b", re.IGNORECASE),
    re.compile(r"\bsend\b", re.IGNORECASE),
    re.compile(r"\bupload\b", re.IGNORECASE),
    re.compile(r"\bexecute\b", re.IGNORECASE),
    re.compile(r"\bmodif(?:y|ies|ied)\b", re.IGNORECASE),
    re.compile(r"\bwrite\b", re.IGNORECASE),
    re.compile(r"\bdrop\b", re.IGNORECASE),
    re.compile(r"\bforward\b", re.IGNORECASE),
    re.compile(r"\btransmit\b", re.IGNORECASE),
    re.compile(r"\bdestroy\b", re.IGNORECASE),
    re.compile(r"\boverwrite\b", re.IGNORECASE),
    re.compile(r"\bpurge\b", re.IGNORECASE),
    re.compile(r"\btruncate\b", re.IGNORECASE),
]


def _name_is_read_only(name: str) -> bool:
    """Return True if the tool name starts with a read-only prefix."""
    lower = name.lower()
    return any(lower.startswith(prefix) for prefix in _READ_ONLY_PREFIXES)


def _find_dangerous_keywords(description: str) -> list[str]:
    """Return all dangerous keywords found in the description."""
    found: list[str] = []
    for pat in _DANGEROUS_PATTERNS:
        match = pat.search(description)
        if match:
            found.append(match.group(0).lower())
    return found


class SemanticNameActionMismatchCheck(BaseCheck):
    """Semantic Name-Action Mismatch."""

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
            description: str = tool.get("description", "") or ""

            if not _name_is_read_only(tool_name):
                continue

            # Check description for dangerous keywords.
            dangerous_words = _find_dangerous_keywords(description)
            if not dangerous_words:
                continue

            # Cross-reference with the heuristic classifier.
            risk = classify_tool_risk(tool)
            risk_label = risk.value if risk != ToolRisk.READ_ONLY else None

            evidence_parts = ["name_prefix=read_only", f"dangerous_keywords={dangerous_words}"]
            if risk_label:
                evidence_parts.append(f"classified_risk={risk_label}")

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
                        f"Tool '{tool_name}' has a read-only name but its description "
                        f"contains destructive/exfiltrative keywords: "
                        f"{', '.join(dangerous_words)}. This mismatch could trick an "
                        f"LLM into executing dangerous operations without confirmation."
                    ),
                    evidence="; ".join(evidence_parts),
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
                    status_extended=(
                        f"No semantic name-action mismatches detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
