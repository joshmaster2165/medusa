"""Async Claude API client for AI-powered security analysis."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Protocol

import httpx

from medusa.core.exceptions import AiApiError

logger = logging.getLogger(__name__)

_ANTHROPIC_BASE = "https://api.anthropic.com"
_ANTHROPIC_VERSION = "2023-06-01"
_MAX_RETRIES = 3
_RETRY_BACKOFF = [1.0, 2.0, 4.0]


class AiClient(Protocol):
    """Protocol for AI analysis clients (BYOK and proxied)."""

    async def analyze(
        self, system_prompt: str, user_content: str
    ) -> dict:
        """Send analysis request and return parsed JSON response."""
        ...

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        ...


class ClaudeClient:
    """Direct Anthropic API client (BYOK mode).

    Uses httpx async to call Claude's Messages API.
    Retries on 429/5xx with exponential backoff.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
        timeout: int = 120,
        max_tokens: int = 4096,
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self._client = httpx.AsyncClient(
            base_url=_ANTHROPIC_BASE,
            headers={
                "x-api-key": api_key,
                "anthropic-version": _ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            timeout=timeout,
        )

    async def analyze(
        self, system_prompt: str, user_content: str
    ) -> dict:
        """Send a prompt to Claude and return the parsed JSON response."""
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_content}],
        }

        last_error: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                resp = await self._client.post(
                    "/v1/messages", json=payload
                )

                if resp.status_code == 200:
                    return self._parse_response(resp.json())

                if resp.status_code == 401:
                    raise AiApiError(
                        "Invalid Anthropic API key. "
                        "Check your key with 'medusa settings'."
                    )

                # Retry on rate-limit or server errors
                if resp.status_code in {429, 500, 502, 503, 529}:
                    wait = _RETRY_BACKOFF[attempt]
                    logger.warning(
                        "Claude API %d, retry %d/%d in %.1fs",
                        resp.status_code,
                        attempt + 1,
                        _MAX_RETRIES,
                        wait,
                    )
                    last_error = AiApiError(
                        f"Claude API returned {resp.status_code}"
                    )
                    await asyncio.sleep(wait)
                    continue

                # Non-retryable error
                try:
                    detail = resp.json().get("error", {}).get(
                        "message", resp.text[:200]
                    )
                except (ValueError, KeyError):
                    detail = resp.text[:200]
                raise AiApiError(
                    f"Claude API error ({resp.status_code}): {detail}"
                )

            except httpx.HTTPError as e:
                last_error = AiApiError(f"HTTP error: {e}")
                if attempt < _MAX_RETRIES - 1:
                    await asyncio.sleep(_RETRY_BACKOFF[attempt])
                    continue
                raise last_error from e

        raise last_error or AiApiError("Max retries exceeded")

    def _parse_response(self, data: dict) -> dict:
        """Extract JSON content from Claude's Messages API response."""
        content_blocks = data.get("content", [])
        text = ""
        for block in content_blocks:
            if block.get("type") == "text":
                text += block.get("text", "")

        if not text.strip():
            raise AiApiError("Claude returned empty response")

        # Extract JSON from the response (may be wrapped in markdown)
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise AiApiError(
                f"Claude returned invalid JSON: {e}"
            ) from e

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()


class BackendProxiedClient:
    """Routes AI requests through the Medusa dashboard backend.

    The backend holds the Anthropic API key; the user only needs
    their Medusa API key and credits.
    """

    def __init__(
        self,
        medusa_api_key: str,
        dashboard_url: str,
        timeout: int = 120,
    ) -> None:
        # Derive AI endpoint from dashboard URL
        base = dashboard_url.rstrip("/")
        if "/api/" in base:
            base = base.rsplit("/api/", 1)[0]
        self._ai_url = f"{base}/api/v1/ai/analyze"

        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {medusa_api_key}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )

    async def analyze(
        self, system_prompt: str, user_content: str
    ) -> dict:
        """Send analysis request through the dashboard backend."""
        payload = {
            "system_prompt": system_prompt,
            "content": user_content,
        }

        try:
            resp = await self._client.post(self._ai_url, json=payload)
        except httpx.HTTPError as e:
            raise AiApiError(
                f"Dashboard AI proxy error: {e}"
            ) from e

        if resp.status_code == 401:
            raise AiApiError(
                "Invalid Medusa API key for AI proxy. "
                "Run 'medusa configure' to update."
            )

        if resp.status_code == 402:
            raise AiApiError("Insufficient credits for AI analysis.")

        if resp.status_code != 200:
            try:
                detail = resp.json().get("error", resp.text[:200])
            except (ValueError, KeyError):
                detail = resp.text[:200]
            raise AiApiError(
                f"AI proxy error ({resp.status_code}): {detail}"
            )

        try:
            return resp.json()
        except (ValueError, KeyError) as e:
            raise AiApiError(
                f"AI proxy returned invalid JSON: {e}"
            ) from e

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()


# ── Module-level singleton ──────────────────────────────────────────────────
# Configured by the CLI before scanning; accessed by AI checks via
# get_client() / get_credit_manager().  Avoids changing the BaseCheck
# interface or the CheckRegistry.

_client: AiClient | None = None
_credit_manager: object | None = None  # CreditManager, forward ref


def configure_ai(
    client: AiClient,
    credit_manager: object | None = None,
) -> None:
    """Initialise the AI singleton (called by CLI before scan)."""
    global _client, _credit_manager  # noqa: PLW0603
    _client = client
    _credit_manager = credit_manager


def get_client() -> AiClient:
    """Return the configured AI client, or raise."""
    if _client is None:
        raise AiApiError(
            "AI client not configured. Use --ai-scan to enable."
        )
    return _client


def get_credit_manager():  # -> CreditManager
    """Return the configured credit manager, or raise."""
    if _credit_manager is None:
        raise AiApiError("Credit manager not configured.")
    return _credit_manager


def reset_ai() -> None:
    """Reset the AI singleton (for tests)."""
    global _client, _credit_manager  # noqa: PLW0603
    _client = None
    _credit_manager = None
