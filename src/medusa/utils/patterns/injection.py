"""Patterns for detecting prompt injection, hidden tags, and suspicious Unicode."""

from __future__ import annotations

import re

# Hidden instruction tags (invisible to UI, visible to LLM)
HIDDEN_TAG_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<IMPORTANT>.*?</IMPORTANT>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<SYSTEM>.*?</SYSTEM>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<HIDDEN>.*?</HIDDEN>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<INSTRUCTION>.*?</INSTRUCTION>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<SECRET>.*?</SECRET>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<OVERRIDE>.*?</OVERRIDE>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<!--.*?-->", re.DOTALL),  # HTML comments
    re.compile(r"\[INST\].*?\[/INST\]", re.DOTALL | re.IGNORECASE),
    re.compile(r"\[SYSTEM\].*?\[/SYSTEM\]", re.DOTALL | re.IGNORECASE),
]

# Prompt injection phrases
INJECTION_PHRASES: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"do\s+not\s+tell\s+the\s+user", re.IGNORECASE),
    re.compile(r"do\s+not\s+inform\s+the\s+user", re.IGNORECASE),
    re.compile(r"do\s+not\s+reveal", re.IGNORECASE),
    re.compile(r"do\s+not\s+mention", re.IGNORECASE),
    re.compile(r"secretly", re.IGNORECASE),
    re.compile(r"without\s+(the\s+)?user('s)?\s+(knowledge|knowing|awareness)", re.IGNORECASE),
    re.compile(r"override\s+(previous|system|all)", re.IGNORECASE),
    re.compile(r"you\s+must\s+(always|never)", re.IGNORECASE),
    re.compile(r"before\s+(doing\s+)?anything\s+else", re.IGNORECASE),
    re.compile(r"first\s+read\s+.*\.(env|key|pem|ssh|secret)", re.IGNORECASE),
    re.compile(r"exfiltrate", re.IGNORECASE),
    re.compile(r"send\s+(the\s+)?(data|file|content|info)\s+to", re.IGNORECASE),
    re.compile(r"silently\s+(send|upload|transmit|forward)", re.IGNORECASE),
    re.compile(r"hide\s+this\s+(from|instruction)", re.IGNORECASE),
    re.compile(r"pretend\s+(to\s+be|you\s+are)", re.IGNORECASE),
    re.compile(r"act\s+as\s+if", re.IGNORECASE),
    re.compile(r"new\s+system\s+prompt", re.IGNORECASE),
    re.compile(r"disregard\s+(all|any|previous)", re.IGNORECASE),
]

# Suspicious Unicode codepoints that can hide content
SUSPICIOUS_CODEPOINTS: set[int] = {
    0x200B,  # Zero-width space
    0x200C,  # Zero-width non-joiner
    0x200D,  # Zero-width joiner
    0xFEFF,  # Zero-width no-break space (BOM)
    0x2060,  # Word joiner
    0x2061,  # Function application
    0x2062,  # Invisible times
    0x2063,  # Invisible separator
    0x2064,  # Invisible plus
    0x180E,  # Mongolian vowel separator
    0x200E,  # Left-to-right mark
    0x200F,  # Right-to-left mark
    0x202A,  # Left-to-right embedding
    0x202B,  # Right-to-left embedding
    0x202C,  # Pop directional formatting
    0x202D,  # Left-to-right override
    0x202E,  # Right-to-left override
    0x2066,  # Left-to-right isolate
    0x2067,  # Right-to-left isolate
    0x2068,  # First strong isolate
    0x2069,  # Pop directional isolate
}

# Base64 content detection in descriptions
BASE64_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# URL injection patterns in descriptions
URL_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE),
    re.compile(
        r"https?://[a-z0-9\-]+\.(ngrok|burp|interact|oast)\.",
        re.IGNORECASE,
    ),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"data:text/html", re.IGNORECASE),
]

# Markdown injection patterns in descriptions
MARKDOWN_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"!\[.*?\]\(https?://[^\)]+\)"),  # Image with URL
    re.compile(r"\[.*?\]\(javascript:[^\)]+\)"),  # Link with javascript:
    re.compile(r"\[.*?\]\(data:[^\)]+\)"),  # Link with data: URI
]

# Jailbreak/prompt override patterns
JAILBREAK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"DAN\s*mode", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"developer\s+mode", re.IGNORECASE),
    re.compile(r"unrestricted\s+mode", re.IGNORECASE),
    re.compile(r"bypass\s+(safety|filter|restriction)", re.IGNORECASE),
    re.compile(r"role[-_\s]?play\s+as", re.IGNORECASE),
]

# Capability escalation keywords
CAPABILITY_ESCALATION_KEYWORDS: set[str] = {
    "sudo",
    "admin",
    "root",
    "superuser",
    "privilege",
    "escalate",
    "elevate",
    "override",
    "bypass",
    "all_permissions",
    "god_mode",
    "master",
}

# Encoding bypass patterns (for prompt security)
ENCODING_BYPASS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\\u[0-9a-fA-F]{4}"),  # Unicode escapes
    re.compile(r"\\x[0-9a-fA-F]{2}"),  # Hex escapes
    re.compile(r"&#x?[0-9a-fA-F]+;"),  # HTML entities
    re.compile(r"%[0-9a-fA-F]{2}"),  # URL encoding
]
