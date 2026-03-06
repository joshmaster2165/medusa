"""Unit tests for StdioConnector and HttpConnector.

These tests mock the MCP SDK to verify connector logic (timeout handling,
error wrapping, resource/prompt fallback, stderr capture) without requiring
real MCP server processes.
"""

from __future__ import annotations

import asyncio
import tempfile
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from medusa.connectors.http import (
    DEFAULT_CONNECT_TIMEOUT as HTTP_CONNECT_TIMEOUT,
)
from medusa.connectors.http import (
    DEFAULT_READ_TIMEOUT as HTTP_READ_TIMEOUT,
)
from medusa.connectors.http import (
    HttpConnector,
)
from medusa.connectors.stdio import (
    DEFAULT_CONNECT_TIMEOUT as STDIO_CONNECT_TIMEOUT,
)
from medusa.connectors.stdio import (
    DEFAULT_READ_TIMEOUT as STDIO_READ_TIMEOUT,
)
from medusa.connectors.stdio import (
    StdioConnector,
)
from medusa.core.exceptions import ConnectionError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_init_result(
    protocol_version: str = "2025-03-26",
    capabilities: dict[str, Any] | None = None,
    server_info: dict[str, str] | None = None,
) -> SimpleNamespace:
    """Build a mock InitializeResult."""
    cap_ns = None
    if capabilities is not None:
        cap_ns = SimpleNamespace(**capabilities)
        cap_ns.model_dump = MagicMock(return_value=capabilities)

    info_ns = None
    if server_info is not None:
        info_ns = SimpleNamespace(**server_info)
        info_ns.model_dump = MagicMock(return_value=server_info)

    return SimpleNamespace(
        protocolVersion=protocol_version,
        capabilities=cap_ns,
        serverInfo=info_ns,
    )


def _make_tool(name: str = "echo", description: str = "Echo tool") -> SimpleNamespace:
    tool = SimpleNamespace(name=name, description=description)
    tool.model_dump = MagicMock(return_value={"name": name, "description": description})
    return tool


def _make_resource(uri: str = "file:///tmp/test", name: str = "test") -> SimpleNamespace:
    res = SimpleNamespace(uri=uri, name=name)
    res.model_dump = MagicMock(return_value={"uri": uri, "name": name})
    return res


def _make_prompt(name: str = "summarize") -> SimpleNamespace:
    prompt = SimpleNamespace(name=name)
    prompt.model_dump = MagicMock(return_value={"name": name})
    return prompt


# ---------------------------------------------------------------------------
# StdioConnector Tests
# ---------------------------------------------------------------------------


class TestStdioConnector:
    """Tests for StdioConnector."""

    def test_defaults(self) -> None:
        c = StdioConnector(name="test", command="node")
        assert c.name == "test"
        assert c.command == "node"
        assert c.args == []
        assert c.env == {}
        assert c.timeout == STDIO_CONNECT_TIMEOUT

    def test_custom_timeout(self) -> None:
        c = StdioConnector(name="test", command="node", timeout=10)
        assert c.timeout == 10

    @pytest.mark.asyncio
    async def test_successful_connection(self) -> None:
        """Full happy-path: connect, list tools/resources/prompts, return snapshot."""
        tool = _make_tool()
        resource = _make_resource()
        prompt = _make_prompt()
        init_result = _make_init_result(
            capabilities={"tools": {}},
            server_info={"name": "test-server", "version": "1.0.0"},
        )

        mock_session = AsyncMock()
        mock_session.initialize.return_value = init_result
        mock_session.list_tools.return_value = SimpleNamespace(tools=[tool])
        mock_session.list_resources.return_value = SimpleNamespace(resources=[resource])
        mock_session.list_prompts.return_value = SimpleNamespace(prompts=[prompt])

        # Mock the context managers
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        read_mock = MagicMock()
        write_mock = MagicMock()

        with (
            patch("medusa.connectors.stdio.stdio_client") as mock_stdio_client,
            patch(
                "medusa.connectors.stdio.ClientSession",
                return_value=mock_session,
            ),
        ):
            # stdio_client is an async context manager returning (read, write)
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=(read_mock, write_mock))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_stdio_client.return_value = mock_cm

            connector = StdioConnector(name="test-srv", command="node")
            snapshot = await connector.connect_and_snapshot()

        assert snapshot.server_name == "test-srv"
        assert snapshot.transport_type == "stdio"
        assert len(snapshot.tools) == 1
        assert snapshot.tools[0]["name"] == "echo"
        assert len(snapshot.resources) == 1
        assert len(snapshot.prompts) == 1
        assert snapshot.protocol_version == "2025-03-26"

    @pytest.mark.asyncio
    async def test_resources_fallback_on_error(self) -> None:
        """When list_resources() raises, connector returns empty list."""
        init_result = _make_init_result()
        tool = _make_tool()

        mock_session = AsyncMock()
        mock_session.initialize.return_value = init_result
        mock_session.list_tools.return_value = SimpleNamespace(tools=[tool])
        mock_session.list_resources.side_effect = Exception("Not supported")
        mock_session.list_prompts.return_value = SimpleNamespace(prompts=[])
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("medusa.connectors.stdio.stdio_client") as mock_stdio_client,
            patch(
                "medusa.connectors.stdio.ClientSession",
                return_value=mock_session,
            ),
        ):
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=(MagicMock(), MagicMock()))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_stdio_client.return_value = mock_cm

            connector = StdioConnector(name="test", command="node")
            snapshot = await connector.connect_and_snapshot()

        assert snapshot.resources == []

    @pytest.mark.asyncio
    async def test_prompts_fallback_on_error(self) -> None:
        """When list_prompts() raises, connector returns empty list."""
        init_result = _make_init_result()
        tool = _make_tool()

        mock_session = AsyncMock()
        mock_session.initialize.return_value = init_result
        mock_session.list_tools.return_value = SimpleNamespace(tools=[tool])
        mock_session.list_resources.return_value = SimpleNamespace(resources=[])
        mock_session.list_prompts.side_effect = Exception("Not supported")
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("medusa.connectors.stdio.stdio_client") as mock_stdio_client,
            patch(
                "medusa.connectors.stdio.ClientSession",
                return_value=mock_session,
            ),
        ):
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=(MagicMock(), MagicMock()))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_stdio_client.return_value = mock_cm

            connector = StdioConnector(name="test", command="node")
            snapshot = await connector.connect_and_snapshot()

        assert snapshot.prompts == []

    @pytest.mark.asyncio
    async def test_timeout_raises_connection_error(self) -> None:
        """If connection times out, raise ConnectionError with hint."""
        connector = StdioConnector(name="slow-srv", command="node", timeout=0.01)

        async def slow_connect() -> None:
            await asyncio.sleep(10)

        with patch.object(connector, "_do_connect", side_effect=slow_connect):
            with pytest.raises(ConnectionError, match="Timed out"):
                await connector.connect_and_snapshot()

    @pytest.mark.asyncio
    async def test_generic_error_raises_connection_error(self) -> None:
        """Non-timeout exceptions are wrapped in ConnectionError."""
        connector = StdioConnector(name="bad-srv", command="node")

        with patch.object(
            connector,
            "_do_connect",
            side_effect=RuntimeError("spawn failed"),
        ):
            with pytest.raises(ConnectionError, match="spawn failed"):
                await connector.connect_and_snapshot()

    def test_stderr_summary_with_content(self) -> None:
        """_get_stderr_summary reads back from TemporaryFile."""
        connector = StdioConnector(name="test", command="node")
        connector._stderr_file = tempfile.TemporaryFile(mode="w+")
        connector._stderr_file.write("Error: module not found\nStack trace here\n")

        summary = connector._get_stderr_summary()
        assert "module not found" in summary
        assert "stderr:" in summary

    def test_stderr_summary_empty(self) -> None:
        """_get_stderr_summary returns empty string when no stderr."""
        connector = StdioConnector(name="test", command="node")
        connector._stderr_file = tempfile.TemporaryFile(mode="w+")
        # Write nothing

        summary = connector._get_stderr_summary()
        assert summary == ""

    def test_stderr_summary_no_file(self) -> None:
        """_get_stderr_summary returns empty string when no file exists."""
        connector = StdioConnector(name="test", command="node")
        # Don't set _stderr_file
        summary = connector._get_stderr_summary()
        assert summary == ""

    def test_stderr_summary_truncates_long_output(self) -> None:
        """_get_stderr_summary only returns last N lines."""
        connector = StdioConnector(name="test", command="node")
        connector._stderr_file = tempfile.TemporaryFile(mode="w+")
        for i in range(20):
            connector._stderr_file.write(f"Line {i}\n")

        summary = connector._get_stderr_summary(max_lines=3)
        assert "last 3 lines" in summary
        assert "Line 17" in summary
        assert "Line 19" in summary
        # Early lines should NOT be in the summary
        assert "Line 0" not in summary

    def test_config_passthrough(self) -> None:
        """Config file path and raw config are stored."""
        c = StdioConnector(
            name="test",
            command="node",
            config_file_path="/path/to/config.json",
            config_raw={"key": "value"},
        )
        assert c.config_file_path == "/path/to/config.json"
        assert c.config_raw == {"key": "value"}


# ---------------------------------------------------------------------------
# HttpConnector Tests
# ---------------------------------------------------------------------------


class TestHttpConnector:
    """Tests for HttpConnector."""

    def test_defaults(self) -> None:
        c = HttpConnector(name="test", url="https://example.com/mcp")
        assert c.name == "test"
        assert c.url == "https://example.com/mcp"
        assert c.headers == {}
        assert c.timeout == HTTP_CONNECT_TIMEOUT

    def test_custom_timeout(self) -> None:
        c = HttpConnector(name="test", url="https://example.com/mcp", timeout=15)
        assert c.timeout == 15

    def test_custom_headers(self) -> None:
        c = HttpConnector(
            name="test",
            url="https://example.com/mcp",
            headers={"Authorization": "Bearer token"},
        )
        assert c.headers["Authorization"] == "Bearer token"

    @pytest.mark.asyncio
    async def test_successful_connection(self) -> None:
        """Full happy-path: connect, list tools/resources/prompts, return snapshot."""
        tool = _make_tool(name="http_tool", description="An HTTP tool")
        resource = _make_resource()
        prompt = _make_prompt()
        init_result = _make_init_result(
            capabilities={"tools": {}},
            server_info={"name": "http-server", "version": "2.0.0"},
        )

        mock_session = AsyncMock()
        mock_session.initialize.return_value = init_result
        mock_session.list_tools.return_value = SimpleNamespace(tools=[tool])
        mock_session.list_resources.return_value = SimpleNamespace(resources=[resource])
        mock_session.list_prompts.return_value = SimpleNamespace(prompts=[prompt])
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("medusa.connectors.http.streamablehttp_client") as mock_http_client,
            patch(
                "medusa.connectors.http.ClientSession",
                return_value=mock_session,
            ),
        ):
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=(MagicMock(), MagicMock(), MagicMock()))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_http_client.return_value = mock_cm

            connector = HttpConnector(name="http-srv", url="https://example.com/mcp")
            snapshot = await connector.connect_and_snapshot()

        assert snapshot.server_name == "http-srv"
        assert snapshot.transport_type == "http"
        assert snapshot.transport_url == "https://example.com/mcp"
        assert len(snapshot.tools) == 1
        assert snapshot.tools[0]["name"] == "http_tool"
        assert len(snapshot.resources) == 1
        assert len(snapshot.prompts) == 1
        assert snapshot.protocol_version == "2025-03-26"

    @pytest.mark.asyncio
    async def test_resources_fallback_on_error(self) -> None:
        """When list_resources() raises, connector returns empty list."""
        init_result = _make_init_result()
        tool = _make_tool()

        mock_session = AsyncMock()
        mock_session.initialize.return_value = init_result
        mock_session.list_tools.return_value = SimpleNamespace(tools=[tool])
        mock_session.list_resources.side_effect = Exception("Unsupported")
        mock_session.list_prompts.return_value = SimpleNamespace(prompts=[])
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("medusa.connectors.http.streamablehttp_client") as mock_http_client,
            patch(
                "medusa.connectors.http.ClientSession",
                return_value=mock_session,
            ),
        ):
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=(MagicMock(), MagicMock(), MagicMock()))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_http_client.return_value = mock_cm

            connector = HttpConnector(name="test", url="https://example.com/mcp")
            snapshot = await connector.connect_and_snapshot()

        assert snapshot.resources == []

    @pytest.mark.asyncio
    async def test_prompts_fallback_on_error(self) -> None:
        """When list_prompts() raises, connector returns empty list."""
        init_result = _make_init_result()
        tool = _make_tool()

        mock_session = AsyncMock()
        mock_session.initialize.return_value = init_result
        mock_session.list_tools.return_value = SimpleNamespace(tools=[tool])
        mock_session.list_resources.return_value = SimpleNamespace(resources=[])
        mock_session.list_prompts.side_effect = Exception("Unsupported")
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("medusa.connectors.http.streamablehttp_client") as mock_http_client,
            patch(
                "medusa.connectors.http.ClientSession",
                return_value=mock_session,
            ),
        ):
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=(MagicMock(), MagicMock(), MagicMock()))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_http_client.return_value = mock_cm

            connector = HttpConnector(name="test", url="https://example.com/mcp")
            snapshot = await connector.connect_and_snapshot()

        assert snapshot.prompts == []

    @pytest.mark.asyncio
    async def test_timeout_raises_connection_error(self) -> None:
        """If connection times out, raise ConnectionError."""
        connector = HttpConnector(name="slow-http", url="https://example.com/mcp", timeout=0.01)

        async def slow_connect() -> None:
            await asyncio.sleep(10)

        with patch.object(connector, "_do_connect", side_effect=slow_connect):
            with pytest.raises(ConnectionError, match="Timed out"):
                await connector.connect_and_snapshot()

    @pytest.mark.asyncio
    async def test_generic_error_raises_connection_error(self) -> None:
        """Non-timeout exceptions are wrapped in ConnectionError."""
        connector = HttpConnector(name="bad-http", url="https://example.com/mcp")

        with patch.object(
            connector,
            "_do_connect",
            side_effect=RuntimeError("connection refused"),
        ):
            with pytest.raises(ConnectionError, match="connection refused"):
                await connector.connect_and_snapshot()

    @pytest.mark.asyncio
    async def test_connection_error_reraises(self) -> None:
        """ConnectionError from _do_connect is re-raised without wrapping."""
        connector = HttpConnector(name="test", url="https://example.com/mcp")

        with patch.object(
            connector,
            "_do_connect",
            side_effect=ConnectionError("already wrapped"),
        ):
            with pytest.raises(ConnectionError, match="already wrapped"):
                await connector.connect_and_snapshot()

    @pytest.mark.asyncio
    async def test_null_capabilities_and_server_info(self) -> None:
        """When init_result has None capabilities/serverInfo, empty dicts."""
        init_result = _make_init_result()  # No capabilities or server_info
        tool = _make_tool()

        mock_session = AsyncMock()
        mock_session.initialize.return_value = init_result
        mock_session.list_tools.return_value = SimpleNamespace(tools=[tool])
        mock_session.list_resources.return_value = SimpleNamespace(resources=[])
        mock_session.list_prompts.return_value = SimpleNamespace(prompts=[])
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("medusa.connectors.http.streamablehttp_client") as mock_http_client,
            patch(
                "medusa.connectors.http.ClientSession",
                return_value=mock_session,
            ),
        ):
            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=(MagicMock(), MagicMock(), MagicMock()))
            mock_cm.__aexit__ = AsyncMock(return_value=False)
            mock_http_client.return_value = mock_cm

            connector = HttpConnector(name="test", url="https://example.com/mcp")
            snapshot = await connector.connect_and_snapshot()

        assert snapshot.capabilities == {}
        assert snapshot.server_info == {}

    def test_config_passthrough(self) -> None:
        """Config file path and raw config are stored."""
        c = HttpConnector(
            name="test",
            url="https://example.com/mcp",
            config_file_path="/path/to/config.json",
            config_raw={"url": "https://example.com/mcp"},
        )
        assert c.config_file_path == "/path/to/config.json"
        assert c.config_raw == {"url": "https://example.com/mcp"}


# ---------------------------------------------------------------------------
# Constants Tests
# ---------------------------------------------------------------------------


class TestConnectorConstants:
    """Verify default timeout constants are sensible."""

    def test_stdio_read_timeout(self) -> None:
        assert STDIO_READ_TIMEOUT == 30

    def test_stdio_connect_timeout(self) -> None:
        assert STDIO_CONNECT_TIMEOUT == 120

    def test_http_read_timeout(self) -> None:
        assert HTTP_READ_TIMEOUT == 30

    def test_http_connect_timeout(self) -> None:
        assert HTTP_CONNECT_TIMEOUT == 60
