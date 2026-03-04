"""Stdio transport connector for local MCP servers."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from medusa.connectors.base import BaseConnector
from medusa.core.check import ServerSnapshot
from medusa.core.exceptions import ConnectionError

logger = logging.getLogger(__name__)

# Default read timeout for MCP protocol messages (seconds).
# Generous to allow npx first-run downloads.
DEFAULT_READ_TIMEOUT = 30

# Overall connection timeout including server startup (seconds).
DEFAULT_CONNECT_TIMEOUT = 120


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
        timeout: int = DEFAULT_CONNECT_TIMEOUT,
    ) -> None:
        self.name = name
        self.command = command
        self.args = args or []
        self.env = env or {}
        self.config_file_path = config_file_path
        self.config_raw = config_raw
        self.timeout = timeout

    async def _do_connect(self) -> ServerSnapshot:
        """Internal connection logic, separated for timeout wrapping."""
        params = StdioServerParameters(
            command=self.command,
            args=self.args,
            env=self.env if self.env else None,
        )

        async with stdio_client(params) as (read, write):
            async with ClientSession(
                read,
                write,
                read_timeout_seconds=timedelta(seconds=DEFAULT_READ_TIMEOUT),
            ) as session:
                init_result = await session.initialize()

                tools_result = await session.list_tools()

                # Some servers don't support resources or prompts;
                # gracefully fall back to empty lists.
                try:
                    resources_result = await session.list_resources()
                    resources = [r.model_dump(mode="json") for r in resources_result.resources]
                except Exception:
                    logger.debug("'%s' does not support list_resources", self.name)
                    resources = []

                try:
                    prompts_result = await session.list_prompts()
                    prompts = [p.model_dump(mode="json") for p in prompts_result.prompts]
                except Exception:
                    logger.debug("'%s' does not support list_prompts", self.name)
                    prompts = []

                return ServerSnapshot(
                    server_name=self.name,
                    transport_type="stdio",
                    transport_url=None,
                    command=self.command,
                    args=self.args,
                    env=self.env,
                    tools=[t.model_dump(mode="json") for t in tools_result.tools],
                    resources=resources,
                    prompts=prompts,
                    capabilities=(
                        init_result.capabilities.model_dump(mode="json")
                        if init_result.capabilities
                        else {}
                    ),
                    protocol_version=init_result.protocolVersion,
                    server_info=(
                        init_result.serverInfo.model_dump(mode="json")
                        if init_result.serverInfo
                        else {}
                    ),
                    config_file_path=self.config_file_path,
                    config_raw=self.config_raw,
                )

    async def connect_and_snapshot(self) -> ServerSnapshot:
        """Connect to the MCP server via stdio and return a snapshot."""
        try:
            return await asyncio.wait_for(self._do_connect(), timeout=self.timeout)
        except TimeoutError:
            raise ConnectionError(
                f"Timed out connecting to '{self.name}' after {self.timeout}s "
                f"(command: {self.command})"
            ) from None
        except ConnectionError:
            raise
        except Exception as e:
            raise ConnectionError(
                f"Failed to connect to stdio server '{self.name}' (command: {self.command}): {e}"
            ) from e
