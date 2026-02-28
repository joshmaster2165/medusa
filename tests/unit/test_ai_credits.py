"""Tests for medusa.ai.credits — CreditManager."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from medusa.ai.credits import CreditCheckResult, CreditManager
from medusa.core.exceptions import CreditError


class TestCreditManager:
    @pytest.mark.asyncio
    async def test_check_balance_success(self):
        mgr = CreditManager(
            api_key="test-key",
            dashboard_url="https://example.com/api/v1/reports",
        )

        mock_resp = httpx.Response(
            status_code=200, json={"available": 42}
        )

        with patch.object(
            mgr._client, "get", new_callable=AsyncMock, return_value=mock_resp
        ):
            balance = await mgr.check_balance()
            assert balance == 42
            assert mgr.remaining == 42

    @pytest.mark.asyncio
    async def test_check_balance_unauthorized(self):
        mgr = CreditManager(api_key="bad", dashboard_url="https://x.com")

        mock_resp = httpx.Response(status_code=401, text="Unauthorized")

        with patch.object(
            mgr._client, "get", new_callable=AsyncMock, return_value=mock_resp
        ):
            with pytest.raises(CreditError, match="Invalid Medusa API key"):
                await mgr.check_balance()

    @pytest.mark.asyncio
    async def test_preflight_sufficient(self):
        mgr = CreditManager(api_key="key", dashboard_url="https://x.com")

        mock_resp = httpx.Response(
            status_code=200,
            json={"available": 10, "required": 3, "sufficient": True},
        )

        with patch.object(
            mgr._client, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            result = await mgr.preflight(required=3)
            assert isinstance(result, CreditCheckResult)
            assert result.sufficient is True
            assert result.available == 10
            assert result.required == 3

    @pytest.mark.asyncio
    async def test_preflight_insufficient(self):
        mgr = CreditManager(api_key="key", dashboard_url="https://x.com")

        mock_resp = httpx.Response(
            status_code=200,
            json={"available": 1, "required": 5, "sufficient": False},
        )

        with patch.object(
            mgr._client, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            result = await mgr.preflight(required=5)
            assert result.sufficient is False

    @pytest.mark.asyncio
    async def test_deduct_success(self):
        mgr = CreditManager(api_key="key", dashboard_url="https://x.com")

        mock_resp = httpx.Response(
            status_code=200,
            json={"success": True, "remaining": 9},
        )

        with patch.object(
            mgr._client, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            ok = await mgr.deduct("ai001", "test-server", "scan-123")
            assert ok is True
            assert mgr.remaining == 9

    @pytest.mark.asyncio
    async def test_deduct_insufficient_returns_false(self):
        mgr = CreditManager(api_key="key", dashboard_url="https://x.com")

        mock_resp = httpx.Response(status_code=402, text="No credits")

        with patch.object(
            mgr._client, "post", new_callable=AsyncMock, return_value=mock_resp
        ):
            ok = await mgr.deduct("ai001", "srv", "scan-1")
            assert ok is False

    @pytest.mark.asyncio
    async def test_deduct_network_error_raises(self):
        mgr = CreditManager(api_key="key", dashboard_url="https://x.com")

        with patch.object(
            mgr._client,
            "post",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("refused"),
        ):
            with pytest.raises(CreditError, match="deduction failed"):
                await mgr.deduct("ai001", "srv", "scan-1")

    @pytest.mark.asyncio
    async def test_remaining_none_before_any_call(self):
        mgr = CreditManager(api_key="key", dashboard_url="https://x.com")
        assert mgr.remaining is None
