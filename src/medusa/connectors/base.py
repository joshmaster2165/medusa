"""Base connector interface for MCP server connections."""

from __future__ import annotations

from abc import ABC, abstractmethod

from medusa.core.check import ServerSnapshot


class BaseConnector(ABC):
    """Base class for MCP server connectors.

    Connectors establish a connection to an MCP server, enumerate its
    capabilities, and return an immutable ServerSnapshot.
    """

    @abstractmethod
    async def connect_and_snapshot(self) -> ServerSnapshot:
        """Connect to the MCP server, gather all data, return a snapshot."""
        ...
