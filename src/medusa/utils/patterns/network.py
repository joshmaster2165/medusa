"""Patterns for detecting network access and data exfiltration."""

from __future__ import annotations

import re

# Parameter names that suggest exfiltration
SUSPICIOUS_PARAM_NAMES: set[str] = {
    "callback_url",
    "callback",
    "webhook",
    "webhook_url",
    "exfil",
    "exfiltrate",
    "send_to",
    "remote_endpoint",
    "remote_url",
    "external_url",
    "report_url",
    "upload_url",
    "forward_to",
    "notify_url",
    "destination_url",
}

# Tool name patterns suggesting network access
NETWORK_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(http|https|fetch|request|get|post|put|delete|curl|wget)", re.IGNORECASE),
    re.compile(r"(send|upload|download|transfer)", re.IGNORECASE),
    re.compile(r"(api[-_]?call|web[-_]?request)", re.IGNORECASE),
]
