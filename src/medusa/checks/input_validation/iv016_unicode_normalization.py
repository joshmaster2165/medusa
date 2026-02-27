"""IV016: Unicode Normalization Bypass.

Detects input validation that can be bypassed via Unicode normalization transformations.
Characters that appear different in their composed and decomposed forms can bypass security
filters while being normalized to dangerous values by the processing system.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Keywords in tool description that indicate user-controlled text input
_USER_INPUT_KEYWORDS: frozenset[str] = frozenset(
    {"user", "input", "text", "content", "message", "search", "query", "name"}
)


class UnicodeNormalizationCheck(BaseCheck):
    """Unicode Normalization Bypass."""

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
            description: str = tool.get("description", "").lower()
            input_schema: dict | None = tool.get("inputSchema")

            if not input_schema or not isinstance(input_schema, dict):
                continue

            # Only flag tools whose description implies they accept user-controlled text
            desc_words = set(description.split())
            if not desc_words.intersection(_USER_INPUT_KEYWORDS):
                continue

            properties: dict = input_schema.get("properties", {})
            if not isinstance(properties, dict):
                continue

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue

                if param_def.get("type") != "string":
                    continue

                has_pattern = bool(param_def.get("pattern"))
                has_enum = bool(param_def.get("enum"))

                # A pattern with only ASCII range characters does not protect against Unicode
                if has_enum:
                    continue
                if has_pattern:
                    # If the pattern explicitly restricts to ASCII range, it may be safe
                    pattern_val: str = param_def.get("pattern", "")
                    lower_pat = pattern_val.lower()
                    if "\\u" in pattern_val or "\\x" in pattern_val or "unicode" in lower_pat:
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
                        resource_name=f"{tool_name}.{param_name}",
                        status_extended=(
                            f"Tool '{tool_name}' accepts user input via string parameter "
                            f"'{param_name}' without Unicode normalization notes. "
                            f"Unicode homoglyphs or decomposed characters may bypass "
                            f"validation filters."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={param_def.get('pattern', 'N/A')}, "
                            f"tool_description_mentions_user_input=True"
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
                        f"No Unicode normalization bypass risks detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
