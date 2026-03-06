"""Patterns for detecting internal implementation leakage in prompts and descriptions."""

from __future__ import annotations

import re

# Patterns matching internal implementation details that should not be exposed
INTERNAL_LEAK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Unix file path", re.compile(r"/(?:usr|var|opt|etc|home|root|tmp|proc|sys)/\S+")),
    ("Windows file path", re.compile(r"[A-Z]:\\\\?\S+")),
    (
        "SQL statement",
        re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\s+", re.IGNORECASE),
    ),
    (
        "Database connection string",
        re.compile(r"(?:mongodb|postgres(?:ql)?|mysql|redis|sqlite|mssql)://\S+", re.IGNORECASE),
    ),
    (
        "Internal hostname",
        re.compile(
            r"(?:internal|private|staging|dev|local)[-.][\w.-]+\.(?:internal|local|corp|lan)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Stack trace",
        re.compile(
            r"(?:at\s+\w+\.[\w.]+\(|Traceback \(most recent|File \".+\", line \d+)", re.IGNORECASE
        ),
    ),
    ("Environment variable reference", re.compile(r"\$\{?[A-Z_]{3,}\}?")),
    ("IP address with port", re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b")),
]
