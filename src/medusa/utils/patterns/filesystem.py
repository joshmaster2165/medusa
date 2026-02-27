"""Patterns for detecting sensitive filesystem paths and filesystem tool access."""

from __future__ import annotations

import re

# Sensitive file path patterns
SENSITIVE_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.(env|pem|key|p12|pfx|jks)$", re.IGNORECASE),
    re.compile(
        r"(credentials|secrets?|tokens?|passwords?)\.(json|yaml|yml|xml|ini|conf)",
        re.IGNORECASE,
    ),
    re.compile(r"\.ssh/", re.IGNORECASE),
    re.compile(r"\.aws/credentials", re.IGNORECASE),
    re.compile(r"\.kube/config", re.IGNORECASE),
    re.compile(r"\.docker/config\.json", re.IGNORECASE),
]

# Tool names suggesting shell execution
SHELL_TOOL_NAMES: set[str] = {
    "exec",
    "execute",
    "run",
    "run_command",
    "shell",
    "bash",
    "terminal",
    "system",
    "subprocess",
    "eval",
    "execute_command",
    "run_shell",
    "cmd",
}

# Tool name patterns suggesting filesystem operations
FS_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(read|write|delete|remove|create|list|move|copy)[-_]?(file|dir|directory|folder)",
        re.IGNORECASE,
    ),
    re.compile(r"file[-_]?(read|write|delete|remove|create|list|move|copy)", re.IGNORECASE),
    re.compile(r"fs[-_]", re.IGNORECASE),
    re.compile(r"filesystem", re.IGNORECASE),
]
