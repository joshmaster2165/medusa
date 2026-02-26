"""Text analysis utilities for examining MCP tool descriptions."""

from __future__ import annotations

import unicodedata

from medusa.utils.pattern_matching import (
    HIDDEN_TAG_PATTERNS,
    INJECTION_PHRASES,
    SUSPICIOUS_CODEPOINTS,
)


def find_hidden_tags(text: str) -> list[str]:
    """Find hidden XML/HTML-style tags in text that may contain injected instructions."""
    matches: list[str] = []
    for pattern in HIDDEN_TAG_PATTERNS:
        for match in pattern.finditer(text):
            content = match.group()
            truncated = content[:200] + "..." if len(content) > 200 else content
            matches.append(truncated)
    return matches


def find_injection_phrases(text: str) -> list[str]:
    """Find prompt injection phrases in text."""
    matches: list[str] = []
    for pattern in INJECTION_PHRASES:
        for match in pattern.finditer(text):
            matches.append(match.group())
    return matches


def find_suspicious_unicode(text: str) -> list[str]:
    """Find invisible or suspicious Unicode characters in text."""
    issues: list[str] = []
    for i, char in enumerate(text):
        cp = ord(char)
        if cp in SUSPICIOUS_CODEPOINTS:
            name = unicodedata.name(char, "UNKNOWN")
            issues.append(f"U+{cp:04X} ({name}) at position {i}")
    return issues


def analyze_description(text: str) -> dict[str, list[str]]:
    """Run all text analysis checks on a description.

    Returns a dict with keys for each type of issue found.
    """
    results: dict[str, list[str]] = {}

    hidden_tags = find_hidden_tags(text)
    if hidden_tags:
        results["hidden_tags"] = hidden_tags

    injection = find_injection_phrases(text)
    if injection:
        results["injection_phrases"] = injection

    unicode_issues = find_suspicious_unicode(text)
    if unicode_issues:
        results["suspicious_unicode"] = unicode_issues

    return results
