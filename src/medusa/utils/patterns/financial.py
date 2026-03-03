"""Patterns for detecting financial transaction capabilities in MCP tools."""

from __future__ import annotations

import re

# Tool names/descriptions suggesting financial operations
FINANCIAL_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(pay|payment|transfer|transaction|wallet)\b", re.IGNORECASE),
    re.compile(r"\b(withdraw|deposit|invoice|billing|charge)\b", re.IGNORECASE),
    re.compile(r"\b(refund|payout|purchase|checkout|subscribe)\b", re.IGNORECASE),
    re.compile(r"(send[-_]?money|wire[-_]?transfer|crypto)", re.IGNORECASE),
    re.compile(r"\b(stripe|paypal|venmo|square|braintree)\b", re.IGNORECASE),
    re.compile(r"\b(bank[-_]?account|credit[-_]?card|debit[-_]?card)\b", re.IGNORECASE),
]
