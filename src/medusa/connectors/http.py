"""HTTP/SSE transport connector for remote MCP servers."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from medusa.connectors.base import BaseConnector
from medusa.core.check import ServerSnapshot
from medusa.core.exceptions import ConnectionError

logger = logging.getLogger(__name__)

# Default read timeout for MCP protocol messages (seconds).
DEFAULT_READ_TIMEOUT = 30

# Overall connection timeout including server response (seconds).
DEFAULT_CONNECT_TIMEOUT = 60


class HttpConnector(BaseConnector):
    """Connect to a remote MCP server via Streamable HTTP transport."""

    def __init__(
        self,
        name: str,
        url: str,
        headers: dict[str, str] | None = None,
        config_file_path: str | None = None,
        config_raw: dict | None = None,
        timeout: int = DEFAULT_CONNECT_TIMEOUT,
    ) -> None:
        self.name = name
        self.url = url
        self.headers = headers or {}
        self.config_file_path = config_file_path
        self.config_raw = config_raw
        self.timeout = timeout

    async def _do_connect(self) -> ServerSnapshot:
        """Internal connection logic, separated for timeout wrapping."""
        async with streamablehttp_client(self.url, headers=self.headers) as (
            read,
            write,
            _,
        ):
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
                    transport_type="http",
                    transport_url=self.url,
                    command=None,
                    args=[],
                    env={},
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
        """Connect to the MCP server via HTTP and return a snapshot."""
        try:
            return await asyncio.wait_for(self._do_connect(), timeout=self.timeout)
        except TimeoutError:
            raise ConnectionError(
                f"Timed out connecting to '{self.name}' after {self.timeout}s (url: {self.url})"
            ) from None
        except ConnectionError:
            raise
        except Exception as e:
            raise ConnectionError(
                f"Failed to connect to HTTP server '{self.name}' (url: {self.url}): {e}"
            ) from e
