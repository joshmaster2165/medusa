"""Medusa Agent — endpoint security daemon for MCP.

Auto-discovers MCP clients, intercepts all traffic through the
gateway proxy, enforces security policies, and reports telemetry
to the Medusa cloud dashboard.
"""

from __future__ import annotations

__all__ = [
    "AgentConfig",
    "AgentDaemon",
    "AgentStore",
]
