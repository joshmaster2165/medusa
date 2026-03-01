"""Tests for medusa.ai.client — Claude API client and singleton management."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from medusa.ai.client import (
    BackendProxiedClient,
    ClaudeClient,
    configure_ai,
    get_client,
    get_credit_manager,
    reset_ai,
)
from medusa.core.exceptions import AiApiError


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Reset the AI singleton between tests."""
    reset_ai()
    yield
    reset_ai()


# ── ClaudeClient ─────────────────────────────────────────────────────────


class TestClaudeClient:
    @pytest.mark.asyncio
    async def test_analyze_success(self):
        """Successful Claude API call returns parsed JSON."""
        client = ClaudeClient(api_key="test-key")

        mock_response = httpx.Response(
            status_code=200,
            json={
                "content": [
                    {
                        "type": "text",
                        "text": '{"findings": []}',
                    }
                ]
            },
        )

        with patch.object(
            client._client, "post", new_callable=AsyncMock, return_value=mock_response
        ):
            result = await client.analyze("system prompt", "user content")
            assert result == {"findings": []}

    @pytest.mark.asyncio
    async def test_analyze_invalid_api_key(self):
        """401 response raises AiApiError about invalid key."""
        client = ClaudeClient(api_key="bad-key")

        mock_response = httpx.Response(status_code=401, text="Unauthorized")

        with patch.object(
            client._client, "post", new_callable=AsyncMock, return_value=mock_response
        ):
            with pytest.raises(AiApiError, match="Invalid Anthropic API key"):
                await client.analyze("system", "content")

    @pytest.mark.asyncio
    async def test_analyze_malformed_json(self):
        """Non-JSON response from Claude raises AiApiError."""
        client = ClaudeClient(api_key="test-key")

        mock_response = httpx.Response(
            status_code=200,
            json={
                "content": [{"type": "text", "text": "not valid json"}]
            },
        )

        with patch.object(
            client._client, "post", new_callable=AsyncMock, return_value=mock_response
        ):
            with pytest.raises(AiApiError, match="invalid JSON"):
                await client.analyze("system", "content")

    @pytest.mark.asyncio
    async def test_analyze_empty_response(self):
        """Empty Claude response raises AiApiError."""
        client = ClaudeClient(api_key="test-key")

        mock_response = httpx.Response(
            status_code=200,
            json={"content": [{"type": "text", "text": ""}]},
        )

        with patch.object(
            client._client, "post", new_callable=AsyncMock, return_value=mock_response
        ):
            with pytest.raises(AiApiError, match="empty response"):
                await client.analyze("system", "content")

    @pytest.mark.asyncio
    async def test_analyze_strips_markdown_fences(self):
        """JSON wrapped in ```json fences is correctly parsed."""
        client = ClaudeClient(api_key="test-key")

        mock_response = httpx.Response(
            status_code=200,
            json={
                "content": [
                    {
                        "type": "text",
                        "text": '```json\n{"findings": []}\n```',
                    }
                ]
            },
        )

        with patch.object(
            client._client, "post", new_callable=AsyncMock, return_value=mock_response
        ):
            result = await client.analyze("system", "content")
            assert result == {"findings": []}

    @pytest.mark.asyncio
    async def test_close(self):
        """close() calls aclose on the underlying client."""
        client = ClaudeClient(api_key="test-key")
        with patch.object(client._client, "aclose", new_callable=AsyncMock) as mock_close:
            await client.close()
            mock_close.assert_called_once()


# ── BackendProxiedClient ─────────────────────────────────────────────────


class TestBackendProxiedClient:
    @pytest.mark.asyncio
    async def test_analyze_success(self):
        """Proxied client returns parsed response."""
        client = BackendProxiedClient(
            medusa_api_key="medusa-key",
            dashboard_url="https://example.com/api/v1/reports",
        )
        assert "example.com" in client._ai_url

        mock_response = httpx.Response(
            status_code=200,
            json={"findings": [{"severity": "high"}]},
        )

        with patch.object(
            client._client, "post", new_callable=AsyncMock, return_value=mock_response
        ):
            result = await client.analyze("system", "content")
            assert "findings" in result

    @pytest.mark.asyncio
    async def test_analyze_insufficient_credits(self):
        """402 from proxy raises AiApiError about credits."""
        client = BackendProxiedClient(
            medusa_api_key="key",
            dashboard_url="https://example.com",
        )

        mock_response = httpx.Response(status_code=402, text="No credits")

        with patch.object(
            client._client, "post", new_callable=AsyncMock, return_value=mock_response
        ):
            with pytest.raises(AiApiError, match="Insufficient credits"):
                await client.analyze("system", "content")

    @pytest.mark.asyncio
    async def test_analyze_retries_on_502(self):
        """502 from proxy triggers retry and succeeds."""
        client = BackendProxiedClient(
            medusa_api_key="key",
            dashboard_url="https://example.com",
        )

        fail_resp = httpx.Response(
            status_code=502, text="Bad Gateway"
        )
        ok_resp = httpx.Response(
            status_code=200,
            json={"findings": []},
        )

        with patch.object(
            client._client,
            "post",
            new_callable=AsyncMock,
            side_effect=[fail_resp, ok_resp],
        ):
            result = await client.analyze("system", "content")
            assert result == {"findings": []}

    @pytest.mark.asyncio
    async def test_analyze_retries_on_429(self):
        """429 rate limit triggers retry and succeeds."""
        client = BackendProxiedClient(
            medusa_api_key="key",
            dashboard_url="https://example.com",
        )

        fail_resp = httpx.Response(
            status_code=429, text="Rate limited"
        )
        ok_resp = httpx.Response(
            status_code=200,
            json={"findings": []},
        )

        with patch.object(
            client._client,
            "post",
            new_callable=AsyncMock,
            side_effect=[fail_resp, ok_resp],
        ):
            result = await client.analyze("system", "content")
            assert result == {"findings": []}

    @pytest.mark.asyncio
    async def test_analyze_max_retries_exceeded(self):
        """All retries exhausted raises AiApiError."""
        client = BackendProxiedClient(
            medusa_api_key="key",
            dashboard_url="https://example.com",
        )

        fail_resp = httpx.Response(
            status_code=502, text="Bad Gateway"
        )

        with patch.object(
            client._client,
            "post",
            new_callable=AsyncMock,
            return_value=fail_resp,
        ):
            with pytest.raises(AiApiError, match="502"):
                await client.analyze("system", "content")

    @pytest.mark.asyncio
    async def test_analyze_401_not_retried(self):
        """401 is not retried — fails immediately."""
        client = BackendProxiedClient(
            medusa_api_key="key",
            dashboard_url="https://example.com",
        )

        mock_response = httpx.Response(
            status_code=401, text="Unauthorized"
        )

        with patch.object(
            client._client,
            "post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ) as mock_post:
            with pytest.raises(AiApiError, match="Invalid Medusa API key"):
                await client.analyze("system", "content")
            # Should only be called once — no retries
            assert mock_post.call_count == 1


# ── Singleton management ─────────────────────────────────────────────────


class TestSingleton:
    def test_get_client_before_configure_raises(self):
        with pytest.raises(AiApiError, match="not configured"):
            get_client()

    def test_get_credit_manager_before_configure_raises(self):
        with pytest.raises(AiApiError, match="not configured"):
            get_credit_manager()

    def test_configure_and_get_client(self):
        mock_client = MagicMock()
        configure_ai(client=mock_client)
        assert get_client() is mock_client

    def test_configure_with_credit_manager(self):
        mock_client = MagicMock()
        mock_credits = MagicMock()
        configure_ai(client=mock_client, credit_manager=mock_credits)
        assert get_credit_manager() is mock_credits

    def test_reset_clears_singleton(self):
        configure_ai(client=MagicMock())
        reset_ai()
        with pytest.raises(AiApiError):
            get_client()
