"""Tests for telemetry manager."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from medusa.agent.models import AgentConfig, TelemetryEvent
from medusa.agent.store import AgentStore
from medusa.agent.telemetry import TelemetryManager


class TestTelemetryManager:
    """Tests for TelemetryManager."""

    def _make_manager(self, tmp_path, **config_kwargs):
        config = AgentConfig(
            customer_id="test-customer",
            api_key="med_test",
            agent_id="test-agent-id",
            **config_kwargs,
        )
        store = AgentStore(db_path=tmp_path / "test.db")
        return TelemetryManager(config, store), store

    def test_init(self, tmp_path):
        manager, store = self._make_manager(tmp_path)
        assert manager._endpoint.endswith("gateway-events")

    @pytest.mark.asyncio
    async def test_upload_empty_batch(self, tmp_path):
        manager, store = self._make_manager(tmp_path)
        result = await manager.upload_batch()
        assert result == {"uploaded": 0, "errors": 0}

    @pytest.mark.asyncio
    async def test_upload_batch_success(self, tmp_path):
        manager, store = self._make_manager(tmp_path)

        # Insert test events
        for i in range(3):
            store.insert_event(
                TelemetryEvent(
                    direction="request",
                    verdict="allow",
                    server_name=f"server-{i}",
                )
            )

        # Mock the HTTP client
        mock_response = AsyncMock()
        mock_response.status_code = 200

        with patch("medusa.agent.telemetry.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await manager.upload_batch()

        assert result["uploaded"] == 3
        assert result["errors"] == 0

        # Events should be marked as uploaded
        pending = store.get_pending_events()
        assert len(pending) == 0

    @pytest.mark.asyncio
    async def test_upload_batch_failure(self, tmp_path):
        manager, store = self._make_manager(tmp_path)

        store.insert_event(TelemetryEvent(verdict="allow"))

        mock_response = AsyncMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        with patch("medusa.agent.telemetry.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await manager.upload_batch()

        assert result["uploaded"] == 0
        assert result["errors"] == 1

        # Events should NOT be marked as uploaded
        pending = store.get_pending_events()
        assert len(pending) == 1

    @pytest.mark.asyncio
    async def test_upload_batch_network_error(self, tmp_path):
        import httpx

        manager, store = self._make_manager(tmp_path)
        store.insert_event(TelemetryEvent(verdict="allow"))

        with patch("medusa.agent.telemetry.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.side_effect = httpx.ConnectError("Connection refused")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await manager.upload_batch()

        assert result["uploaded"] == 0
        assert result["errors"] == 1

    def test_serialize_event(self):
        event = TelemetryEvent(
            id="test-id",
            timestamp="2025-01-01T00:00:00Z",
            direction="request",
            message_type="tools/call",
            tool_name="read_file",
            server_name="test-server",
            verdict="block",
            rule_name="tool_blocked",
            reason="Blocked",
        )
        serialized = TelemetryManager._serialize_event(event)
        assert serialized["id"] == "test-id"
        assert serialized["verdict"] == "block"
        assert serialized["tool_name"] == "read_file"
        assert "uploaded" not in serialized  # Not included in upload
        assert "agent_id" not in serialized  # Not per-event
