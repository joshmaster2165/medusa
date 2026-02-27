"""Integration test fixtures — spin up real mock MCP servers via stdio."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from medusa.connectors.stdio import StdioConnector

MOCK_SERVER_PATH = str(Path(__file__).parent / "mock_server.py")


def _make_connector(profile: str) -> StdioConnector:
    """Create a StdioConnector that launches the mock server."""
    return StdioConnector(
        name=f"mock-{profile}",
        command=sys.executable,
        args=[MOCK_SERVER_PATH, profile],
    )


@pytest.fixture()
def vulnerable_connector() -> StdioConnector:
    """Connector to the *vulnerable* mock MCP server."""
    return _make_connector("vulnerable")


@pytest.fixture()
def secure_connector() -> StdioConnector:
    """Connector to the *secure* mock MCP server."""
    return _make_connector("secure")


@pytest.fixture()
def empty_connector() -> StdioConnector:
    """Connector to the *empty* mock MCP server."""
    return _make_connector("empty")
