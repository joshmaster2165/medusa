"""Tool capability classifier for toxic flow and risk analysis.

Inspired by Snyk agent-scan's ScalarToolLabels model, this module classifies
MCP tools into capability dimensions using numeric risk scores. Each tool is
scored across five dimensions: untrusted_input, private_data, public_sink,
destructive, and financial.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from medusa.utils.patterns.filesystem import DESTRUCTIVE_TOOL_PATTERNS, SHELL_TOOL_NAMES

# ── Classification patterns ──────────────────────────────────────────────

# Tools that accept external/user-controlled content
UNTRUSTED_INPUT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(fetch|get|read|receive|accept|listen|poll|subscribe)[-_]?"
        r"(url|http|web|email|message|request|webhook|event|feed|rss|api)",
        re.IGNORECASE,
    ),
    re.compile(r"(web[-_]?search|scrape|crawl|spider|download)", re.IGNORECASE),
    re.compile(r"(user[-_]?input|stdin|prompt[-_]?user|ask[-_]?user)", re.IGNORECASE),
    re.compile(r"(import|ingest|load[-_]?external|pull[-_]?data)", re.IGNORECASE),
]

UNTRUSTED_INPUT_DESCRIPTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(fetch|download|retrieve|pull)s?\s+(data|content|page|url|file)s?\s+from", re.IGNORECASE
    ),
    re.compile(
        r"accept.*\b(user|external|untrusted|remote)\b.*\b(input|data|content)\b", re.IGNORECASE
    ),
    re.compile(
        r"(read|receive|listen)s?\s+(from\s+)?(external|remote|network|internet)", re.IGNORECASE
    ),
    re.compile(r"search(es)?\s+(the\s+)?(web|internet|online)", re.IGNORECASE),
]

# Tools that access private/sensitive data
PRIVATE_DATA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(read|get|query|list|fetch|access|retrieve|dump|export)[-_]?"
        r"(file|db|database|table|record|user|credential|secret|token|key|env|config|log|password)",
        re.IGNORECASE,
    ),
    re.compile(r"(sql|query)[-_]?(exec|execute|run|select)", re.IGNORECASE),
    re.compile(r"(access|read)[-_]?(secret|credential|password|private|sensitive)", re.IGNORECASE),
    re.compile(r"(get|list|read)[-_]?(users?|accounts?|profiles?|contacts?)", re.IGNORECASE),
]

PRIVATE_DATA_DESCRIPTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(access|read|query|retrieve).*\b(private|sensitive|confidential|secret)\b", re.IGNORECASE
    ),
    re.compile(
        r"(database|file\s*system|filesystem|credential|secret|token|password)", re.IGNORECASE
    ),
    re.compile(r"(read|access|list).*\b(user|account|profile)\b.*\bdata\b", re.IGNORECASE),
]

# Tools that send data to external destinations
PUBLIC_SINK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(send|post|push|publish|upload|write|transmit|forward|relay|emit)[-_]?"
        r"(email|message|webhook|http|data|file|notification|alert|slack|discord|teams)",
        re.IGNORECASE,
    ),
    re.compile(r"(http[-_]?post|api[-_]?call|rest[-_]?call|webhook)", re.IGNORECASE),
    re.compile(r"(notify|alert|broadcast|announce)[-_]?", re.IGNORECASE),
    re.compile(
        r"(slack|discord|teams|telegram|email)[-_]?(send|post|message|notify)", re.IGNORECASE
    ),
    re.compile(r"(upload|export|share)[-_]?(file|data|report|document)", re.IGNORECASE),
]

PUBLIC_SINK_DESCRIPTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(send|post|push|publish|upload|transmit|forward)s?\s+.*(to|via)\b", re.IGNORECASE),
    re.compile(r"(write|export)s?\s+(data|content|file)s?\s+to\s+(external|remote)", re.IGNORECASE),
    re.compile(
        r"\b(email|slack|discord|webhook|http\s*post)\b.*\b(send|post|notify)\b", re.IGNORECASE
    ),
]

# Destructive tool description patterns (supplements existing name patterns)
DESTRUCTIVE_DESCRIPTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(delete|remove|drop|truncate|destroy|purge|wipe|erase)s?\s+", re.IGNORECASE),
    re.compile(r"(permanently|irreversibly)\s+(delete|remove|destroy)", re.IGNORECASE),
]


@dataclass
class ToolLabels:
    """Numeric risk scores per capability dimension.

    Inspired by Snyk's ScalarToolLabels model. Each dimension is scored
    0.0 (no match) or 1.0 (matched). Future refinement can use fractional
    scores for confidence-based classification.
    """

    untrusted_input: float = 0.0
    private_data: float = 0.0
    public_sink: float = 0.0
    destructive: float = 0.0
    financial: float = 0.0
    matched_categories: dict[str, list[str]] = field(default_factory=dict)


def _check_patterns(
    text: str,
    name_patterns: list[re.Pattern[str]],
    desc_patterns: list[re.Pattern[str]] | None = None,
    description: str = "",
) -> list[str]:
    """Check text against name patterns and description against desc patterns.

    Returns list of matched pattern snippets for evidence.
    """
    hits: list[str] = []
    for pat in name_patterns:
        m = pat.search(text)
        if m:
            hits.append(m.group()[:80])
    if desc_patterns and description:
        for pat in desc_patterns:
            m = pat.search(description)
            if m:
                hits.append(m.group()[:80])
    return hits


def classify_tool(tool: dict) -> ToolLabels:
    """Score a single tool across risk dimensions.

    Examines tool name, description, and inputSchema property names.
    """
    # Lazy import to avoid circular dependency at module level
    from medusa.utils.patterns.financial import FINANCIAL_TOOL_PATTERNS

    name = tool.get("name", "")
    description = tool.get("description", "")
    # Combine name and description for broader matching
    text = f"{name} {description}"
    schema = tool.get("inputSchema", {})
    schema_props = " ".join(schema.get("properties", {}).keys()) if isinstance(schema, dict) else ""
    full_text = f"{text} {schema_props}"

    labels = ToolLabels()

    # untrusted_input
    hits = _check_patterns(
        name, UNTRUSTED_INPUT_PATTERNS, UNTRUSTED_INPUT_DESCRIPTION_PATTERNS, description
    )
    if hits:
        labels.untrusted_input = 1.0
        labels.matched_categories["untrusted_input"] = hits

    # private_data
    hits = _check_patterns(
        name, PRIVATE_DATA_PATTERNS, PRIVATE_DATA_DESCRIPTION_PATTERNS, description
    )
    if hits:
        labels.private_data = 1.0
        labels.matched_categories["private_data"] = hits

    # public_sink
    hits = _check_patterns(
        name, PUBLIC_SINK_PATTERNS, PUBLIC_SINK_DESCRIPTION_PATTERNS, description
    )
    if hits:
        labels.public_sink = 1.0
        labels.matched_categories["public_sink"] = hits

    # destructive — use existing Medusa patterns + description patterns
    name_lower = name.lower()
    dest_hits: list[str] = []
    if name_lower in SHELL_TOOL_NAMES:
        dest_hits.append(f"shell_tool:{name_lower}")
    for pat in DESTRUCTIVE_TOOL_PATTERNS:
        m = pat.search(name)
        if m:
            dest_hits.append(m.group()[:80])
    for pat in DESTRUCTIVE_DESCRIPTION_PATTERNS:
        m = pat.search(description)
        if m:
            dest_hits.append(m.group()[:80])
    if dest_hits:
        labels.destructive = 1.0
        labels.matched_categories["destructive"] = dest_hits

    # financial
    fin_hits: list[str] = []
    for pat in FINANCIAL_TOOL_PATTERNS:
        m = pat.search(full_text)
        if m:
            fin_hits.append(m.group()[:80])
    if fin_hits:
        labels.financial = 1.0
        labels.matched_categories["financial"] = fin_hits

    return labels


def classify_tools(tools: list[dict]) -> dict[str, ToolLabels]:
    """Classify all tools on a server.

    Returns a dict mapping tool name to its ToolLabels.
    """
    return {tool.get("name", f"unknown_{i}"): classify_tool(tool) for i, tool in enumerate(tools)}
