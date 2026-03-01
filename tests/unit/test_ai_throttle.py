"""Tests for medusa.ai.throttle — dynamic AI check concurrency."""

from __future__ import annotations

import pytest

from medusa.ai.throttle import (
    CONCURRENCY_LARGE,
    CONCURRENCY_MEDIUM,
    CONCURRENCY_SMALL,
    acquire_ai_slot,
    compute_concurrency,
    configure_throttle,
    estimate_snapshot_size,
    release_ai_slot,
    reset_throttle,
)
from tests.conftest import make_snapshot


@pytest.fixture(autouse=True)
def _reset():
    reset_throttle()
    yield
    reset_throttle()


# ── estimate_snapshot_size ─────────────────────────────────────────────


class TestEstimateSnapshotSize:
    def test_empty_snapshot(self):
        snap = make_snapshot()
        size = estimate_snapshot_size(snap)
        assert size == 0

    def test_snapshot_with_tools(self):
        snap = make_snapshot(
            tools=[{"name": "read_file", "description": "Read a file"}]
        )
        size = estimate_snapshot_size(snap)
        assert size > 0

    def test_snapshot_with_resources(self):
        snap = make_snapshot(
            resources=[{"uri": "file:///tmp/data", "name": "data"}]
        )
        size = estimate_snapshot_size(snap)
        assert size > 0

    def test_large_snapshot(self):
        big_tools = [
            {"name": f"tool_{i}", "description": "x" * 1000}
            for i in range(50)
        ]
        snap = make_snapshot(tools=big_tools)
        size = estimate_snapshot_size(snap)
        assert size > 50_000

    def test_includes_capabilities(self):
        snap = make_snapshot(
            capabilities={"tools": {"listChanged": True}}
        )
        size = estimate_snapshot_size(snap)
        assert size > 0

    def test_includes_config_raw(self):
        snap = make_snapshot(config_raw={"server": {"port": 3000}})
        size = estimate_snapshot_size(snap)
        assert size > 0


# ── compute_concurrency ───────────────────────────────────────────────


class TestComputeConcurrency:
    def test_small(self):
        assert compute_concurrency(5_000) == CONCURRENCY_SMALL

    def test_medium(self):
        assert compute_concurrency(50_000) == CONCURRENCY_MEDIUM

    def test_large(self):
        assert compute_concurrency(200_000) == CONCURRENCY_LARGE

    def test_boundary_small_medium(self):
        assert compute_concurrency(19_999) == CONCURRENCY_SMALL
        assert compute_concurrency(20_000) == CONCURRENCY_MEDIUM

    def test_boundary_medium_large(self):
        assert compute_concurrency(99_999) == CONCURRENCY_MEDIUM
        assert compute_concurrency(100_000) == CONCURRENCY_LARGE

    def test_zero(self):
        assert compute_concurrency(0) == CONCURRENCY_SMALL


# ── configure_throttle ────────────────────────────────────────────────


class TestConfigureThrottle:
    def test_first_server_sets_concurrency(self):
        snap = make_snapshot()  # empty → small
        c = configure_throttle(snap)
        assert c == CONCURRENCY_SMALL

    def test_larger_server_tightens(self):
        small = make_snapshot()
        configure_throttle(small)

        big = make_snapshot(
            tools=[
                {"name": f"t{i}", "description": "x" * 2000}
                for i in range(100)
            ]
        )
        c = configure_throttle(big)
        assert c == CONCURRENCY_LARGE

    def test_smaller_server_does_not_loosen(self):
        big = make_snapshot(
            tools=[
                {"name": f"t{i}", "description": "x" * 2000}
                for i in range(100)
            ]
        )
        configure_throttle(big)

        small = make_snapshot()
        c = configure_throttle(small)
        # Should keep the tighter limit
        assert c == CONCURRENCY_LARGE

    def test_equal_concurrency_keeps_existing(self):
        snap1 = make_snapshot(tools=[{"name": "a", "description": "b"}])
        c1 = configure_throttle(snap1)

        snap2 = make_snapshot(tools=[{"name": "c", "description": "d"}])
        c2 = configure_throttle(snap2)

        assert c1 == c2  # both small


# ── acquire / release ─────────────────────────────────────────────────


class TestAcquireRelease:
    @pytest.mark.asyncio
    async def test_no_throttle_configured(self):
        """When no throttle is configured, acquire/release are no-ops."""
        await acquire_ai_slot()
        release_ai_slot()

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(self):
        snap = make_snapshot()
        configure_throttle(snap)  # CONCURRENCY_SMALL = 4

        # All slots should be acquirable
        for _ in range(CONCURRENCY_SMALL):
            await acquire_ai_slot()

        # Release them all
        for _ in range(CONCURRENCY_SMALL):
            release_ai_slot()


# ── reset_throttle ────────────────────────────────────────────────────


class TestResetThrottle:
    @pytest.mark.asyncio
    async def test_reset_allows_reconfiguration(self):
        big = make_snapshot(
            tools=[
                {"name": f"t{i}", "description": "x" * 2000}
                for i in range(100)
            ]
        )
        configure_throttle(big)
        assert configure_throttle(make_snapshot()) == CONCURRENCY_LARGE

        reset_throttle()

        # After reset, small snapshot gets full concurrency
        c = configure_throttle(make_snapshot())
        assert c == CONCURRENCY_SMALL
