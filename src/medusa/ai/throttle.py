"""Dynamic throttling for AI check concurrency.

The module-level semaphore is shared by all AI checks across all servers.
Concurrency is dynamically computed from snapshot size to avoid overwhelming
Claude API rate limits (50 RPM, 40K input tokens/min).
"""

from __future__ import annotations

import asyncio
import json
import logging
import random

from medusa.core.check import ServerSnapshot

logger = logging.getLogger(__name__)

# ── Concurrency tiers ──────────────────────────────────────────────────
# Thresholds are in characters of the JSON-serialized snapshot payload.
# Rough approximation: ~4 chars per token on average.

TIER_SMALL_THRESHOLD = 20_000  # < 20K chars → ~5K tokens
TIER_MEDIUM_THRESHOLD = 100_000  # 20K-100K chars → 5K-25K tokens

CONCURRENCY_SMALL = 8
CONCURRENCY_MEDIUM = 4
CONCURRENCY_LARGE = 2

# Jitter range (seconds) added before each AI call to stagger bursts
JITTER_MIN = 0.1
JITTER_MAX = 1.0

# ── Module-level state ─────────────────────────────────────────────────

_semaphore: asyncio.Semaphore | None = None
_concurrency: int = CONCURRENCY_MEDIUM


def estimate_snapshot_size(snapshot: ServerSnapshot) -> int:
    """Estimate the character count of the snapshot's AI payload.

    Mirrors what ``build_analysis_payload()`` serializes: tools,
    resources, prompts, capabilities, and config_raw as JSON.
    """
    total = 0
    for collection in (snapshot.tools, snapshot.resources, snapshot.prompts):
        if collection:
            total += len(json.dumps(collection, default=str))
    if snapshot.capabilities:
        total += len(json.dumps(snapshot.capabilities, default=str))
    if snapshot.config_raw:
        total += len(json.dumps(snapshot.config_raw, default=str))
    return total


def compute_concurrency(snapshot_size: int) -> int:
    """Determine the AI check concurrency limit from snapshot size."""
    if snapshot_size < TIER_SMALL_THRESHOLD:
        return CONCURRENCY_SMALL
    elif snapshot_size < TIER_MEDIUM_THRESHOLD:
        return CONCURRENCY_MEDIUM
    else:
        return CONCURRENCY_LARGE


def configure_throttle(snapshot: ServerSnapshot) -> int:
    """(Re)configure the global AI semaphore for a given snapshot.

    Called once per server before its AI checks run.  If the new
    concurrency is *lower* than the current one the semaphore is
    replaced (conservative).  If higher, the existing (tighter)
    semaphore is kept — multi-server scans use the most conservative
    limit seen so far.

    Returns the concurrency value in effect.
    """
    global _semaphore, _concurrency  # noqa: PLW0603

    size = estimate_snapshot_size(snapshot)
    new_concurrency = compute_concurrency(size)

    if _semaphore is None:
        # First server — create the semaphore
        _concurrency = new_concurrency
        _semaphore = asyncio.Semaphore(new_concurrency)
        logger.info(
            "AI throttle: snapshot=%d chars, concurrency=%d",
            size,
            new_concurrency,
        )
    elif new_concurrency < _concurrency:
        # New server has a bigger snapshot — tighten the limit
        _concurrency = new_concurrency
        _semaphore = asyncio.Semaphore(new_concurrency)
        logger.info(
            "AI throttle: tightened to concurrency=%d (snapshot=%d chars)",
            new_concurrency,
            size,
        )
    else:
        logger.info(
            "AI throttle: keeping concurrency=%d "
            "(new snapshot=%d chars would allow %d)",
            _concurrency,
            size,
            new_concurrency,
        )

    return _concurrency


async def acquire_ai_slot() -> None:
    """Acquire a slot from the global AI semaphore.

    Must be paired with :func:`release_ai_slot`.  Adds random jitter
    after acquisition to stagger burst requests.
    """
    if _semaphore is None:
        # No throttle configured — allow execution (static-only mode
        # or tests that don't set up throttling).
        return

    await _semaphore.acquire()

    # Jitter: small random delay so requests released at the same
    # instant don't all hit Claude simultaneously.
    jitter = random.uniform(JITTER_MIN, JITTER_MAX)
    await asyncio.sleep(jitter)


def release_ai_slot() -> None:
    """Release a slot back to the global AI semaphore."""
    if _semaphore is not None:
        _semaphore.release()


def reset_throttle() -> None:
    """Reset throttle state (for tests and between scans)."""
    global _semaphore, _concurrency  # noqa: PLW0603
    _semaphore = None
    _concurrency = CONCURRENCY_MEDIUM
