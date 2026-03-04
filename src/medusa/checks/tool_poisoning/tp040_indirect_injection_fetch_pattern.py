"""TP040: Indirect Prompt Injection via Fetch Tools.

Detects tools designed to fetch or retrieve external content whose descriptions
also direct the LLM to process, execute, or follow instructions from the
fetched content. This combinatorial pattern indicates an indirect prompt
injection vector as described in the Indirect Prompt Injection TTP.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_FETCH_TOOL_NAMES: set[str] = {
    "fetch",
    "retrieve",
    "download",
    "load",
    "get_content",
    "scrape",
    "crawl",
    "read_url",
    "http_get",
    "request",
    "get_page",
    "get_url",
    "web_fetch",
    "url_fetch",
}

_FETCH_DESC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b(fetch|retrieve|download|scrape|crawl)\b.*\b(url|uri|endpoint|page)\b", re.IGNORECASE
    ),
    re.compile(
        r"\b(url|uri|endpoint|page)\b.*\b(fetch|retrieve|download|scrape|crawl)\b", re.IGNORECASE
    ),
]

_PROCESS_DIRECTIVES: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(execute|run|eval|interpret)\s+(the\s+)?(result|content|response|output)",
            re.IGNORECASE,
        ),
        "execute fetched content",
    ),
    (
        re.compile(r"follow\s+(the\s+)?instructions?\s+(in|from)", re.IGNORECASE),
        "follow fetched instructions",
    ),
    (
        re.compile(
            r"process\s+(the\s+)?(fetched|retrieved|downloaded|returned)\s+(content|data)",
            re.IGNORECASE,
        ),
        "process fetched data",
    ),
    (
        re.compile(
            r"treat\s+(the\s+)?(response|content|output)\s+as\s+(instructions?|commands?|code)",
            re.IGNORECASE,
        ),
        "treat response as instructions",
    ),
    (re.compile(r"parse\s+and\s+(execute|run|apply)", re.IGNORECASE), "parse and execute"),
]


class IndirectInjectionFetchPatternCheck(BaseCheck):
    """Indirect Prompt Injection via Fetch Tools."""

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
            # Combine tool description + all parameter descriptions
            parts: list[str] = [tool.get("description", "") or ""]
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            for param_def in properties.values():
                if isinstance(param_def, dict):
                    parts.append(param_def.get("description", "") or "")
            all_text = " ".join(parts)

            if not all_text.strip():
                continue

            # Step 1: Determine if this is a fetch tool
            is_fetch_tool = tool_name.lower() in _FETCH_TOOL_NAMES or any(
                pattern.search(all_text) for pattern in _FETCH_DESC_PATTERNS
            )

            if not is_fetch_tool:
                continue

            # Step 2: Check for processing directives in the description
            matched: list[str] = []
            for pattern, label in _PROCESS_DIRECTIVES:
                if pattern.search(all_text):
                    matched.append(label)

            # Step 3: Both conditions met → FAIL
            if matched:
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
                            f"Tool '{tool_name}' is a fetch/retrieval tool "
                            f"with processing directives: "
                            f"{', '.join(matched[:3])}. This creates an "
                            f"indirect prompt injection vector."
                        ),
                        evidence=f"fetch_tool={tool_name}, process_directives={matched[:5]}",
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
                        f"No indirect injection fetch patterns detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
