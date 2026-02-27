"""Patterns for detecting hardcoded secrets and credentials."""

from __future__ import annotations

import re

# Secret patterns for detecting hardcoded credentials
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i:aws)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    ("GitHub Personal Access Token", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    (
        "Generic API Key",
        re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?"),
    ),
    (
        "Generic Secret",
        re.compile(r"(?i)(secret|password|passwd|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?"),
    ),
    ("Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9]{10,}-[A-Za-z0-9-]+")),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9\-]{32,}")),
    ("Stripe Key", re.compile(r"[sr]k_(live|test)_[A-Za-z0-9]{20,}")),
    ("Private Key Header", re.compile(r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE\s+KEY-----")),
]
