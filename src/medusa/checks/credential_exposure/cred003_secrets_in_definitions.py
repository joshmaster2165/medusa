"""CRED-003: Secrets in Tool Definitions.

Scans tool, resource, and prompt descriptions and URIs for embedded secrets
using the project's standard SECRET_PATTERNS.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import SECRET_PATTERNS


def _redact(value: str, keep: int = 4) -> str:
    """Redact a secret value, keeping only the first few characters."""
    if len(value) <= keep:
        return "***"
    return value[:keep] + "***"


def _scan_text(text: str) -> list[tuple[str, str]]:
    """Scan a text string for secret patterns.

    Returns list of (pattern_name, matched_value) tuples.
    """
    hits: list[tuple[str, str]] = []
    for pattern_name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            hits.append((pattern_name, match.group()))
    return hits


def _extract_strings_from_schema(schema: dict | None) -> list[str]:
    """Extract all string values from a JSON Schema (inputSchema).

    Looks at descriptions, defaults, enum values, and examples that might
    accidentally contain secrets.
    """
    if not schema:
        return []

    strings: list[str] = []

    def _walk(obj: dict | list | str) -> None:
        if isinstance(obj, str):
            strings.append(obj)
        elif isinstance(obj, dict):
            for key, value in obj.items():
                if key in ("description", "default", "title", "examples"):
                    if isinstance(value, str):
                        strings.append(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str):
                                strings.append(item)
                if isinstance(value, (dict, list)):
                    _walk(value)
                # Also check enum values.
                if key == "enum" and isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            strings.append(item)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(schema)
    return strings


class SecretsInDefinitionsCheck(BaseCheck):
    """Check for secrets embedded in tool/resource/prompt definitions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # --- Scan tools ---
        for tool in snapshot.tools:
            tool_name = tool.get("name", "unknown")
            texts_to_scan: list[str] = []

            if tool.get("description"):
                texts_to_scan.append(tool["description"])

            # Scan inputSchema for secrets in defaults, descriptions, etc.
            input_schema = tool.get("inputSchema")
            if input_schema:
                texts_to_scan.extend(_extract_strings_from_schema(input_schema))

            for text in texts_to_scan:
                for pattern_name, matched in _scan_text(text):
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
                                f"Embedded {pattern_name} found in definition "
                                f"of tool '{tool_name}' on server "
                                f"'{snapshot.server_name}'. This secret is "
                                f"visible to all connected clients and may be "
                                f"forwarded to language models."
                            ),
                            evidence=f"{pattern_name}: {_redact(matched)}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # --- Scan resources ---
        for resource in snapshot.resources:
            resource_name = resource.get("name", "unknown")
            texts_to_scan = []

            if resource.get("description"):
                texts_to_scan.append(resource["description"])
            if resource.get("uri"):
                texts_to_scan.append(resource["uri"])

            for text in texts_to_scan:
                for pattern_name, matched in _scan_text(text):
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="resource",
                            resource_name=resource_name,
                            status_extended=(
                                f"Embedded {pattern_name} found in definition "
                                f"of resource '{resource_name}' on server "
                                f"'{snapshot.server_name}'. This secret is "
                                f"broadcast to all connected clients."
                            ),
                            evidence=f"{pattern_name}: {_redact(matched)}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # --- Scan prompts ---
        for prompt in snapshot.prompts:
            prompt_name = prompt.get("name", "unknown")
            texts_to_scan = []

            if prompt.get("description"):
                texts_to_scan.append(prompt["description"])

            # Scan prompt argument descriptions.
            for arg in prompt.get("arguments", []):
                if isinstance(arg, dict) and arg.get("description"):
                    texts_to_scan.append(arg["description"])

            for text in texts_to_scan:
                for pattern_name, matched in _scan_text(text):
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
                                f"Embedded {pattern_name} found in definition "
                                f"of prompt '{prompt_name}' on server "
                                f"'{snapshot.server_name}'. This secret is "
                                f"visible to all connected clients."
                            ),
                            evidence=f"{pattern_name}: {_redact(matched)}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # If nothing was found, emit a PASS.
        if not findings:
            total_defs = (
                len(snapshot.tools)
                + len(snapshot.resources)
                + len(snapshot.prompts)
            )
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
                        f"No embedded secrets found across {total_defs} "
                        f"tool/resource/prompt definition(s) on server "
                        f"'{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
