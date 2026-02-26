"""BaseCheck abstract class and ServerSnapshot data structure."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from medusa.core.models import CheckMetadata, Finding


@dataclass(frozen=True)
class ServerSnapshot:
    """Immutable snapshot of a connected MCP server's state.

    This is the only data a check receives. Checks never get a live connection,
    ensuring they cannot invoke tools or modify server state.
    """

    server_name: str
    transport_type: str  # "stdio" | "http" | "sse"
    transport_url: str | None = None
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    tools: list[dict] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    prompts: list[dict] = field(default_factory=list)
    capabilities: dict = field(default_factory=dict)
    protocol_version: str = ""
    server_info: dict = field(default_factory=dict)
    config_file_path: str | None = None
    config_raw: dict | None = None


class BaseCheck(ABC):
    """Base class all security checks must inherit from.

    Every check implements two methods:
    - metadata(): returns CheckMetadata loaded from the .metadata.yaml sidecar
    - execute(): runs the check against a ServerSnapshot and returns findings
    """

    @abstractmethod
    def metadata(self) -> CheckMetadata:
        """Return the check's metadata."""
        ...

    @abstractmethod
    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        """Execute the security check against a server snapshot.

        Returns a list of Finding objects:
        - Zero findings if the check is not applicable
        - One finding with status PASS if the server passed
        - One or more findings with status FAIL (one per affected resource)
        """
        ...
