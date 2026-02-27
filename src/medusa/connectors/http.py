"""HTTP/SSE transport connector for remote MCP servers."""

from __future__ import annotations

import logging

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from medusa.connectors.base import BaseConnector
from medusa.core.check import ServerSnapshot
from medusa.core.exceptions import ConnectionError

logger = logging.getLogger(__name__)


class HttpConnector(BaseConnector):
    """Connect to a remote MCP server via Streamable HTTP transport."""

    def __init__(
        self,
        name: str,
        url: str,
        headers: dict[str, str] | None = None,
        config_file_path: str | None = None,
        config_raw: dict | None = None,
    ) -> None:
        self.name = name
        self.url = url
        self.headers = headers or {}
        self.config_file_path = config_file_path
        self.config_raw = config_raw

    async def connect_and_snapshot(self) -> ServerSnapshot:
        """Connect to the MCP server via HTTP and return a snapshot."""
        try:
            async with streamablehttp_client(self.url, headers=self.headers) as (read, write, _):
                async with ClientSession(read, write) as session:
                    init_result = await session.initialize()

                    tools_result = await session.list_tools()
                    resources_result = await session.list_resources()
                    prompts_result = await session.list_prompts()

                    return ServerSnapshot(
                        server_name=self.name,
                        transport_type="http",
                        transport_url=self.url,
                        command=None,
                        args=[],
                        env={},
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
                            init_result.serverInfo.model_dump() if init_result.serverInfo else {}
                        ),
                        config_file_path=self.config_file_path,
                        config_raw=self.config_raw,
                    )
        except Exception as e:
            raise ConnectionError(
                f"Failed to connect to HTTP server '{self.name}' (url: {self.url}): {e}"
            ) from e
