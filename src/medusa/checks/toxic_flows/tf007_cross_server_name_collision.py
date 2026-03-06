"""TF-007: Cross-Server Tool Name Collision.

When multiple MCP servers expose tools with the same name or near-identical
names, the LLM cannot reliably distinguish between them.  An attacker who
controls one server can shadow a trusted tool on another server, causing the
LLM to invoke the malicious version instead.

This is a **cross-server** check: it compares tool names across all
scanned server snapshots.  The scanner calls ``execute_cross_server()``
after individual server scans complete.  The regular ``execute()`` returns
an empty list since collision detection requires multiple snapshots.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Near-collision normalisation: lowercase + strip common prefixes/suffixes
# so "get_user" on server A collides with "getUser" on server B.
_STRIP_PREFIXES = ("get_", "set_", "list_", "create_", "delete_", "update_")
_STRIP_SUFFIXES = ("_tool", "_action", "_handler")


def _normalise(name: str) -> str:
    """Normalise a tool name for near-collision detection.

    Lowercases, replaces hyphens/camelCase boundaries with underscores,
    then strips common prefixes/suffixes.
    """
    # camelCase -> snake_case
    normalised = ""
    for i, ch in enumerate(name):
        if ch.isupper() and i > 0 and name[i - 1].islower():
            normalised += "_"
        normalised += ch.lower()
    normalised = normalised.replace("-", "_")

    # Strip common prefixes/suffixes
    for pfx in _STRIP_PREFIXES:
        if normalised.startswith(pfx) and len(normalised) > len(pfx):
            normalised = normalised[len(pfx) :]
            break
    for sfx in _STRIP_SUFFIXES:
        if normalised.endswith(sfx) and len(normalised) > len(sfx):
            normalised = normalised[: -len(sfx)]
            break

    return normalised


class CrossServerNameCollisionCheck(BaseCheck):
    """Detect tool name collisions across multiple MCP servers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # Single-server execution is a no-op; the real logic is in
        # execute_cross_server() which the scanner calls post-scan.
        return []

    async def execute_cross_server(
        self,
        snapshots: list[ServerSnapshot],
    ) -> list[Finding]:
        """Compare tool names across all server snapshots.

        Detects:
        1. **Exact collisions** — same tool name on different servers.
        2. **Near collisions** — normalised names match (camelCase vs snake_case,
           common prefix/suffix differences).
        """
        meta = self.metadata()
        findings: list[Finding] = []

        if len(snapshots) < 2:
            return findings

        # Build indexes: name -> list of (server_name, original_tool_name)
        exact_index: dict[str, list[tuple[str, str]]] = defaultdict(list)
        normal_index: dict[str, list[tuple[str, str, str]]] = defaultdict(list)

        for snap in snapshots:
            for tool in snap.tools:
                tool_name: str = tool.get("name", "")
                if not tool_name:
                    continue
                exact_index[tool_name.lower()].append((snap.server_name, tool_name))
                norm = _normalise(tool_name)
                normal_index[norm].append((snap.server_name, tool_name, tool_name.lower()))

        # Track reported collisions to avoid duplicates
        reported: set[frozenset[tuple[str, str]]] = set()

        # 1. Exact collisions
        for _lower_name, entries in exact_index.items():
            # Only flag when different servers share the same name
            servers = {e[0] for e in entries}
            if len(servers) < 2:
                continue

            collision_key = frozenset((e[0], e[1]) for e in entries)
            if collision_key in reported:
                continue
            reported.add(collision_key)

            server_list = ", ".join(sorted(servers))
            original_name = entries[0][1]

            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=server_list,
                    server_transport="multi",
                    resource_type="tool",
                    resource_name=original_name,
                    status_extended=(
                        f"Tool '{original_name}' exists on multiple servers: "
                        f"{server_list}. An attacker controlling one server "
                        f"can shadow the trusted tool, causing the LLM to "
                        f"invoke the malicious version."
                    ),
                    evidence=(
                        f"collision_type=exact, tool_name={original_name}, servers=[{server_list}]"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        # 2. Near collisions (normalised names match but exact names differ)
        for _norm, entries in normal_index.items():
            servers = {e[0] for e in entries}
            if len(servers) < 2:
                continue

            # Group by exact lowercase to skip already-reported exact matches
            exact_groups: dict[str, set[str]] = defaultdict(set)
            for server_name, _orig, lower in entries:
                exact_groups[lower].add(server_name)

            # If all entries share the same lowercase name, it's an exact
            # collision already reported above.
            if len(exact_groups) < 2:
                continue

            collision_key = frozenset((e[0], e[1]) for e in entries)
            if collision_key in reported:
                continue
            reported.add(collision_key)

            server_tools = [f"{e[0]}:{e[1]}" for e in entries]
            # Deduplicate to unique server entries
            unique_servers = sorted({e[0] for e in entries})

            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=", ".join(unique_servers),
                    server_transport="multi",
                    resource_type="tool",
                    resource_name=entries[0][1],
                    status_extended=(
                        f"Near-collision detected: tools "
                        f"{', '.join(repr(e[1]) for e in entries)} "
                        f"across servers {', '.join(unique_servers)} "
                        f"normalise to the same name. The LLM may confuse "
                        f"these tools, enabling tool shadowing attacks."
                    ),
                    evidence=(f"collision_type=near, normalised={_norm}, tools={server_tools}"),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        # PASS if multi-server and no collisions found
        if not findings and len(snapshots) >= 2:
            all_servers = ", ".join(sorted(s.server_name for s in snapshots))
            total_tools = sum(len(s.tools) for s in snapshots)
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=all_servers,
                    server_transport="multi",
                    resource_type="server",
                    resource_name="cross-server",
                    status_extended=(
                        f"No tool name collisions detected across "
                        f"{len(snapshots)} servers ({total_tools} tools)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
