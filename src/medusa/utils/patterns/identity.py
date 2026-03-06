"""Patterns for PII detection and generic/confusable server names."""

from __future__ import annotations

import re

# PII detection patterns (for data protection checks)
PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Email Address", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("US Phone Number", re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")),
    ("US SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("Credit Card Number", re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")),
    ("IPv4 Address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

# Generic / confusable server names (for shadow server detection)
GENERIC_SERVER_NAMES: set[str] = {
    "server",
    "mcp",
    "default",
    "test",
    "dev",
    "local",
    "main",
    "my-server",
    "myserver",
    "untitled",
    "new-server",
    "example",
    "demo",
    "tmp",
    "temp",
}

# Known MCP protocol versions
KNOWN_MCP_PROTOCOL_VERSIONS: list[str] = ["2025-03-26", "2024-11-05", "2024-10-07"]

# Current stable MCP protocol version
CURRENT_MCP_PROTOCOL_VERSION: str = "2025-03-26"
