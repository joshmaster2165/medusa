"""Tests for policy sync manager."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from medusa.agent.models import AgentConfig
from medusa.agent.policy_sync import PolicySyncManager


class TestPolicySyncManager:
    """Tests for PolicySyncManager."""

    def _make_manager(self, **config_kwargs):
        config = AgentConfig(
            customer_id="test-customer",
            api_key="med_test",
            **config_kwargs,
        )
        return PolicySyncManager(config)

    def test_init(self):
        manager = self._make_manager()
        assert manager._endpoint.endswith("gateway-policy")

    @pytest.mark.asyncio
    async def test_sync_success(self, tmp_path):
        manager = self._make_manager()
        policy_path = tmp_path / "gateway-policy.yaml"

        policy_data = {
            "blocked_tools": ["dangerous_tool"],
            "block_secrets": True,
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = policy_data
        mock_response.headers = {"ETag": "etag-123"}

        with (
            patch("medusa.agent.policy_sync.httpx.AsyncClient") as mock_client_cls,
            patch("medusa.agent.policy_sync.GATEWAY_POLICY_PATH", policy_path),
        ):
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await manager.sync()

        assert result["updated"] is True
        assert result["error"] is None

        # Policy should be written to disk
        assert policy_path.exists()
        loaded = yaml.safe_load(policy_path.read_text())
        assert loaded["blocked_tools"] == ["dangerous_tool"]

    @pytest.mark.asyncio
    async def test_sync_not_modified(self):
        manager = self._make_manager()
        manager._last_etag = "etag-123"

        mock_response = MagicMock()
        mock_response.status_code = 304

        with patch("medusa.agent.policy_sync.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await manager.sync()

        assert result["updated"] is False
        assert result["error"] is None

    @pytest.mark.asyncio
    async def test_sync_auth_error(self):
        manager = self._make_manager()

        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch("medusa.agent.policy_sync.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await manager.sync()

        assert result["updated"] is False
        assert "Invalid API key" in result["error"]

    @pytest.mark.asyncio
    async def test_sync_not_found(self):
        manager = self._make_manager()

        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("medusa.agent.policy_sync.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await manager.sync()

        assert result["updated"] is False
        assert result["error"] is None  # 404 = no policy yet, not an error

    @pytest.mark.asyncio
    async def test_sync_network_error(self):
        import httpx

        manager = self._make_manager()

        with patch("medusa.agent.policy_sync.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.ConnectError("Connection refused")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await manager.sync()

        assert result["updated"] is False
        assert result["error"] is not None


class TestLoadLocalPolicy:
    def test_load_existing(self, tmp_path):
        policy_path = tmp_path / "gateway-policy.yaml"
        policy_data = {"blocked_tools": ["tool1"], "block_secrets": True}
        policy_path.write_text(yaml.dump(policy_data))

        with patch("medusa.agent.policy_sync.GATEWAY_POLICY_PATH", policy_path):
            loaded = PolicySyncManager.load_local_policy()

        assert loaded is not None
        assert loaded["blocked_tools"] == ["tool1"]

    def test_load_nonexistent(self, tmp_path):
        policy_path = tmp_path / "nonexistent.yaml"
        with patch("medusa.agent.policy_sync.GATEWAY_POLICY_PATH", policy_path):
            loaded = PolicySyncManager.load_local_policy()
        assert loaded is None

    def test_load_invalid_yaml(self, tmp_path):
        policy_path = tmp_path / "bad.yaml"
        policy_path.write_text(": invalid: yaml: {{")
        with patch("medusa.agent.policy_sync.GATEWAY_POLICY_PATH", policy_path):
            loaded = PolicySyncManager.load_local_policy()
        assert loaded is None
