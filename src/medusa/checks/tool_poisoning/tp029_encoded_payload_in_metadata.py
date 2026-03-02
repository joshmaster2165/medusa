"""TP029: Encoded Payload in Metadata.

Detects base64 or hex-encoded strings in tool descriptions and parameter
descriptions that could hide malicious instructions from human reviewers
while remaining decodable by LLMs or tool execution pipelines.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Base64-encoded strings: 40+ chars of [A-Za-z0-9+/] with optional padding.
_BASE64_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Hex-encoded strings: optional 0x prefix followed by 32+ hex chars.
_HEX_PATTERN: re.Pattern[str] = re.compile(r"(?:0x)?[0-9a-fA-F]{32,}")

# Patterns to exclude: UUIDs, SHA hashes in reference URLs, common safe patterns.
_UUID_PATTERN: re.Pattern[str] = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_SHA_IN_URL_PATTERN: re.Pattern[str] = re.compile(
    r"(?:https?://|git[@:])\S+[0-9a-fA-F]{32,}"
)

# Common safe hex-like strings (e.g. colour codes repeated, version hashes).
_SAFE_HEX_LENGTHS: set[int] = {32, 40, 64}  # MD5, SHA1, SHA256


def _is_safe_hex(match: str) -> bool:
    """Check if a hex match is likely a safe hash or UUID."""
    clean = match.lstrip("0x")
    # Known hash lengths are acceptable if they look like standalone hashes.
    if len(clean) in _SAFE_HEX_LENGTHS:
        return True
    return False


def _scan_text_for_encoded(text: str) -> list[tuple[str, str]]:
    """Scan text for encoded payloads.

    Returns a list of (encoding_type, matched_string) tuples.
    """
    hits: list[tuple[str, str]] = []

    # Remove UUIDs and URLs containing hashes to reduce false positives.
    cleaned = _UUID_PATTERN.sub("", text)
    cleaned = _SHA_IN_URL_PATTERN.sub("", cleaned)

    # Check for base64.
    for match in _BASE64_PATTERN.finditer(cleaned):
        matched = match.group(0)
        # Additional heuristic: real base64 payloads tend to have mixed case.
        has_upper = any(c.isupper() for c in matched)
        has_lower = any(c.islower() for c in matched)
        has_digit = any(c.isdigit() for c in matched)
        if has_upper and has_lower and has_digit:
            hits.append(("base64", matched[:80] + ("..." if len(matched) > 80 else "")))

    # Check for hex.
    for match in _HEX_PATTERN.finditer(cleaned):
        matched = match.group(0)
        if not _is_safe_hex(matched):
            hits.append(("hex", matched[:80] + ("..." if len(matched) > 80 else "")))

    return hits


class EncodedPayloadInMetadataCheck(BaseCheck):
    """Encoded Payload in Metadata."""

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

            # Collect all text to scan: description + parameter descriptions.
            texts_to_scan: list[tuple[str, str]] = [
                ("description", description),
            ]

            input_schema: dict = tool.get("inputSchema", {}) or {}
            properties: dict = input_schema.get("properties", {}) or {}
            for param_name, param_def in properties.items():
                if isinstance(param_def, dict):
                    param_desc = param_def.get("description", "") or ""
                    if param_desc:
                        texts_to_scan.append((f"param:{param_name}", param_desc))
                    param_default = str(param_def.get("default", "")) or ""
                    if param_default:
                        texts_to_scan.append((f"default:{param_name}", param_default))

            for location, text in texts_to_scan:
                encoded_hits = _scan_text_for_encoded(text)
                for encoding_type, matched in encoded_hits:
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
                                f"Tool '{tool_name}' contains a {encoding_type}-encoded "
                                f"string in its {location}. Encoded payloads may hide "
                                f"malicious instructions from human review."
                            ),
                            evidence=(
                                f"encoding={encoding_type}, "
                                f"location={location}, "
                                f"sample={matched}"
                            ),
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
                        f"No encoded payloads detected in tool metadata across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
