"""Stdio transport connector for local MCP servers."""

from __future__ import annotations

import logging

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from medusa.connectors.base import BaseConnector
from medusa.core.check import ServerSnapshot
from medusa.core.exceptions import ConnectionError

logger = logging.getLogger(__name__)


class StdioConnector(BaseConnector):
    """Connect to a local MCP server via stdio transport."""

    def __init__(
        self,
        name: str,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        config_file_path: str | None = None,
        config_raw: dict | None = None,
    ) -> None:
        self.name = name
        self.command = command
        self.args = args or []
        self.env = env or {}
        self.config_file_path = config_file_path
        self.config_raw = config_raw

    async def connect_and_snapshot(self) -> ServerSnapshot:
        """Connect to the MCP server via stdio and return a snapshot."""
        params = StdioServerParameters(
            command=self.command,
            args=self.args,
            env=self.env if self.env else None,
        )

        try:
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    init_result = await session.initialize()

                    tools_result = await session.list_tools()
                    resources_result = await session.list_resources()
                    prompts_result = await session.list_prompts()

                    return ServerSnapshot(
                        server_name=self.name,
                        transport_type="stdio",
                        transport_url=None,
                        command=self.command,
                        args=self.args,
                        env=self.env,
                        tools=[t.model_dump() for t in tools_result.tools],
                        resources=[r.model_dump() for r in resources_result.resources],
                        prompts=[p.model_dump() for p in prompts_result.prompts],
                        capabilities=(
                            init_result.capabilities.model_dump()
                            if init_result.capabilities
                            else {}
                        ),
                        protocol_version=init_result.protocolVersion,
                        server_info=(
                            init_result.serverInfo.model_dump()
                            if init_result.serverInfo
                            else {}
                        ),
                        config_file_path=self.config_file_path,
                        config_raw=self.config_raw,
                    )
        except Exception as e:
            raise ConnectionError(
                f"Failed to connect to stdio server '{self.name}' "
                f"(command: {self.command}): {e}"
            ) from e
