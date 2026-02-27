"""Hashing utilities for tool definition integrity checks."""

from __future__ import annotations

import hashlib
import json


def hash_tool_definition(tool: dict) -> str:
    """Compute a SHA-256 hash of a tool definition for drift detection.

    The hash covers the tool name, description, and input schema, serialized
    in a canonical JSON format to ensure deterministic hashing.
    """
    canonical = {
        "name": tool.get("name", ""),
        "description": tool.get("description", ""),
        "inputSchema": tool.get("inputSchema", {}),
    }
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


def hash_server_tools(tools: list[dict]) -> dict[str, str]:
    """Compute hashes for all tools on a server.

    Returns a dict mapping tool name to its SHA-256 hash.
    """
    return {
        tool.get("name", f"unknown_{i}"): hash_tool_definition(tool) for i, tool in enumerate(tools)
    }


def compute_baseline(servers: dict[str, list[dict]]) -> dict[str, dict[str, str]]:
    """Compute a full baseline of tool hashes across multiple servers.

    Args:
        servers: dict mapping server name to list of tool definitions

    Returns:
        dict mapping server name to dict of tool name -> hash
    """
    return {server_name: hash_server_tools(tools) for server_name, tools in servers.items()}


def compare_baseline(
    current: dict[str, str],
    baseline: dict[str, str],
) -> dict[str, str]:
    """Compare current tool hashes against a baseline.

    Returns a dict describing changes:
    - "added": tool exists in current but not baseline
    - "removed": tool exists in baseline but not current
    - "modified": tool exists in both but hash differs
    """
    changes: dict[str, str] = {}

    for name in current:
        if name not in baseline:
            changes[name] = "added"
        elif current[name] != baseline[name]:
            changes[name] = "modified"

    for name in baseline:
        if name not in current:
            changes[name] = "removed"

    return changes
