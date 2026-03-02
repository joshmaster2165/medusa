"""Token budget management for AI reasoning payloads.

Estimates token counts and splits findings into chunks that fit
within the Claude API's context window alongside the server snapshot.
"""

from __future__ import annotations

import json

from medusa.core.check import ServerSnapshot
from medusa.core.models import Finding, Status

# Rough estimate: ~4 characters per token (conservative for mixed content)
CHARS_PER_TOKEN = 4

# Budget reserves
SYSTEM_PROMPT_TOKENS = 2_000
OUTPUT_RESERVE_TOKENS = 8_192


def estimate_snapshot_tokens(snapshot: ServerSnapshot) -> int:
    """Estimate token count for the server snapshot portion."""
    total_chars = 0
    for collection in (snapshot.tools, snapshot.resources, snapshot.prompts):
        if collection:
            total_chars += len(json.dumps(collection, default=str))
    if snapshot.capabilities:
        total_chars += len(
            json.dumps(snapshot.capabilities, default=str)
        )
    if snapshot.config_raw:
        total_chars += len(json.dumps(snapshot.config_raw, default=str))
    # Add overhead for server name, transport, section headers
    total_chars += 200
    return total_chars // CHARS_PER_TOKEN


def estimate_finding_tokens(finding: Finding) -> int:
    """Estimate token count for a single finding in compact format."""
    text = (
        f"{finding.check_id} {finding.check_title} "
        f"{finding.resource_type}/{finding.resource_name} "
        f"{finding.status_extended[:200]} "
        f"{(finding.evidence or '')[:150]}"
    )
    return len(text) // CHARS_PER_TOKEN


def chunk_findings_for_reasoning(
    snapshot: ServerSnapshot,
    findings: list[Finding],
    max_tokens_per_chunk: int = 100_000,
) -> list[list[Finding]]:
    """Split findings into chunks that fit within the token budget.

    The server snapshot is sent with every chunk, so its size is
    subtracted from the available budget.  Findings are grouped by
    category prefix (e.g. ``tp``, ``iv``) to maintain coherence.

    Parameters
    ----------
    snapshot:
        The server snapshot (used to estimate fixed overhead).
    findings:
        All findings from the static scan.
    max_tokens_per_chunk:
        Maximum input tokens per API call (default 100K for Sonnet).

    Returns
    -------
    A list of finding-lists.  Each inner list fits within the token
    budget alongside the snapshot.
    """
    snapshot_tokens = estimate_snapshot_tokens(snapshot)
    overhead = (
        SYSTEM_PROMPT_TOKENS + OUTPUT_RESERVE_TOKENS + snapshot_tokens
    )
    available = max_tokens_per_chunk - overhead

    if available <= 0:
        # Snapshot alone exceeds budget — degrade gracefully
        available = 5_000

    # Only FAIL findings need reasoning (PASS findings add noise/tokens)
    fail_findings = [f for f in findings if f.status == Status.FAIL]

    if not fail_findings:
        # No failures to reason about
        return [findings]

    # Group by category prefix for coherent reasoning
    by_category: dict[str, list[Finding]] = {}
    for f in fail_findings:
        prefix = f.check_id.rstrip("0123456789_")
        by_category.setdefault(prefix, []).append(f)

    chunks: list[list[Finding]] = []
    current_chunk: list[Finding] = []
    current_tokens = 0

    for _category, cat_findings in sorted(by_category.items()):
        cat_tokens = sum(
            estimate_finding_tokens(f) for f in cat_findings
        )

        if current_tokens + cat_tokens <= available:
            current_chunk.extend(cat_findings)
            current_tokens += cat_tokens
        else:
            # Current category doesn't fit — start a new chunk
            if current_chunk:
                chunks.append(current_chunk)
            # If a single category is too large, include it anyway
            # (the API will truncate if needed)
            current_chunk = list(cat_findings)
            current_tokens = cat_tokens

    if current_chunk:
        chunks.append(current_chunk)

    # If everything fits in one chunk, return ALL findings
    # (including PASS) so the AI has full context
    if len(chunks) <= 1:
        return [findings]

    return chunks
