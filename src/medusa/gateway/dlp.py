"""Data Loss Prevention scanner for MCP gateway traffic.

Re-uses Medusa's existing credential and pattern detection libraries
to inspect MCP message payloads in real-time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from medusa.utils.patterns.credentials import SECRET_PATTERNS

# ── PII patterns ────────────────────────────────────────────────────────

_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Email Address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    ("US SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    (
        "Credit Card",
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
        ),
    ),
    ("US Phone", re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("IPv4 Address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

# ── Source code patterns ────────────────────────────────────────────────

_CODE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Python Import", re.compile(r"^\s*(?:from\s+\w+\s+)?import\s+\w+", re.MULTILINE)),
    ("Function Def", re.compile(r"^\s*(?:def|function|fn|func)\s+\w+\s*\(", re.MULTILINE)),
    ("Class Def", re.compile(r"^\s*class\s+\w+", re.MULTILINE)),
    (
        "SQL Query",
        re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\s+", re.IGNORECASE),
    ),
]


class DLPCategory(StrEnum):
    """Category of DLP detection."""

    SECRET = "secret"
    PII = "pii"
    SOURCE_CODE = "source_code"


@dataclass
class DLPFinding:
    """A single DLP detection in message content."""

    category: DLPCategory
    pattern_name: str
    matched_text: str  # Redacted snippet
    context: str  # Where in the message it was found


def _redact(text: str, keep: int = 4) -> str:
    """Redact a matched value for safe logging."""
    if len(text) <= keep:
        return "***"
    return text[:keep] + "***" + text[-2:]


class DLPScanner:
    """Scans MCP message payloads for sensitive data.

    Runs synchronously (all regex-based, sub-millisecond) so it can
    be called in the hot path of the gateway proxy.
    """

    def __init__(
        self,
        *,
        scan_secrets: bool = True,
        scan_pii: bool = True,
        scan_code: bool = False,
    ) -> None:
        self.scan_secrets = scan_secrets
        self.scan_pii = scan_pii
        self.scan_code = scan_code

    def scan_text(self, text: str, context: str = "") -> list[DLPFinding]:
        """Scan a text string for sensitive data."""
        findings: list[DLPFinding] = []

        if self.scan_secrets:
            for name, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(text):
                    findings.append(
                        DLPFinding(
                            category=DLPCategory.SECRET,
                            pattern_name=name,
                            matched_text=_redact(match.group()),
                            context=context,
                        )
                    )

        if self.scan_pii:
            for name, pattern in _PII_PATTERNS:
                for match in pattern.finditer(text):
                    findings.append(
                        DLPFinding(
                            category=DLPCategory.PII,
                            pattern_name=name,
                            matched_text=_redact(match.group()),
                            context=context,
                        )
                    )

        if self.scan_code:
            code_hits = 0
            for name, pattern in _CODE_PATTERNS:
                if pattern.search(text):
                    code_hits += 1
            # Only flag as source code if multiple indicators found
            if code_hits >= 2:
                findings.append(
                    DLPFinding(
                        category=DLPCategory.SOURCE_CODE,
                        pattern_name="Source Code Block",
                        matched_text=f"({code_hits} code indicators found)",
                        context=context,
                    )
                )

        return findings

    def scan_value(self, value: Any, path: str = "") -> list[DLPFinding]:
        """Recursively scan a JSON value (dict, list, string)."""
        findings: list[DLPFinding] = []

        if isinstance(value, str):
            findings.extend(self.scan_text(value, context=path))
        elif isinstance(value, dict):
            for key, val in value.items():
                child_path = f"{path}.{key}" if path else key
                findings.extend(self.scan_value(val, child_path))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                findings.extend(self.scan_value(item, f"{path}[{i}]"))

        return findings

    def scan_message_payload(self, message: dict[str, Any]) -> list[DLPFinding]:
        """Scan an entire MCP JSON-RPC message for sensitive data.

        Inspects:
        - Tool call arguments (params.arguments)
        - Tool call results (result.content)
        - Resource content (result.contents)
        """
        findings: list[DLPFinding] = []
        params = message.get("params", {})
        result = message.get("result", {})

        # Scan tool call arguments
        if args := params.get("arguments"):
            findings.extend(self.scan_value(args, "params.arguments"))

        # Scan tool result content
        if content := result.get("content"):
            findings.extend(self.scan_value(content, "result.content"))

        # Scan resource contents
        if contents := result.get("contents"):
            findings.extend(self.scan_value(contents, "result.contents"))

        # Scan any text fields in params
        for key in ("uri", "url", "query", "prompt", "message"):
            if val := params.get(key):
                findings.extend(self.scan_value(val, f"params.{key}"))

        return findings
