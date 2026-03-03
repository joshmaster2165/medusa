"""Persistent change detection for MCP server configurations.

Tracks tool/resource/prompt hashes across scans and detects changes.
Inspired by Snyk agent-scan's check_server_changed() pattern.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from medusa.utils.hashing import compare_baseline, hash_server_tools

logger = logging.getLogger(__name__)

HISTORY_DIR = Path("~/.config/medusa/scan_history/").expanduser()


def _ensure_history_dir() -> None:
    """Create the history directory if it doesn't exist."""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)


def save_snapshot(server_tool_map: dict[str, list[dict]]) -> None:
    """Save current tool hashes per server as a timestamped snapshot.

    Args:
        server_tool_map: dict mapping server name to list of tool dicts
    """
    _ensure_history_dir()

    snapshot: dict[str, Any] = {
        "timestamp": time.time(),
        "servers": {},
    }

    for server_name, tools in server_tool_map.items():
        snapshot["servers"][server_name] = hash_server_tools(tools)

    # Save with timestamp-based filename
    filename = f"snapshot_{int(time.time())}.json"
    filepath = HISTORY_DIR / filename
    filepath.write_text(json.dumps(snapshot, indent=2))
    logger.debug("Saved scan snapshot: %s", filepath)

    # Keep only last 50 snapshots
    _cleanup_old_snapshots(keep=50)


def _cleanup_old_snapshots(keep: int = 50) -> None:
    """Remove old snapshots, keeping only the most recent N."""
    snapshots = sorted(HISTORY_DIR.glob("snapshot_*.json"))
    if len(snapshots) > keep:
        for old in snapshots[: len(snapshots) - keep]:
            old.unlink()
            logger.debug("Removed old snapshot: %s", old)


def load_last_snapshot() -> dict[str, dict[str, str]] | None:
    """Load the most recent snapshot.

    Returns:
        dict mapping server name to {tool_name: hash}, or None if no history.
    """
    _ensure_history_dir()

    snapshots = sorted(HISTORY_DIR.glob("snapshot_*.json"))
    if not snapshots:
        return None

    latest = snapshots[-1]
    try:
        data = json.loads(latest.read_text())
        return data.get("servers", {})
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load snapshot %s: %s", latest, e)
        return None


def detect_changes(
    server_tool_map: dict[str, list[dict]],
) -> dict[str, list[dict]]:
    """Compare current scan against last snapshot and detect changes.

    Args:
        server_tool_map: dict mapping server name to list of tool dicts

    Returns:
        dict mapping server name to list of change records:
        [{"type": "tool_added"|"tool_removed"|"tool_modified", "name": "..."}, ...]
        Empty dict if no previous snapshot or no changes.
    """
    previous = load_last_snapshot()
    if previous is None:
        return {}

    all_changes: dict[str, list[dict]] = {}

    # Current server hashes
    current_servers: dict[str, dict[str, str]] = {}
    for server_name, tools in server_tool_map.items():
        current_servers[server_name] = hash_server_tools(tools)

    # Detect per-server tool changes
    all_server_names = set(current_servers.keys()) | set(previous.keys())
    for server_name in all_server_names:
        changes: list[dict] = []

        if server_name not in previous:
            changes.append({"type": "server_added", "name": server_name})
        elif server_name not in current_servers:
            changes.append({"type": "server_removed", "name": server_name})
        else:
            tool_changes = compare_baseline(
                current_servers[server_name],
                previous[server_name],
            )
            for tool_name, change_type in tool_changes.items():
                changes.append({"type": f"tool_{change_type}", "name": tool_name})

        if changes:
            all_changes[server_name] = changes

    return all_changes
