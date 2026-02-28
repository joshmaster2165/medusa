"""Credit manager for AI-powered scanning."""

from __future__ import annotations

import logging

import httpx

from medusa.core.exceptions import CreditError

logger = logging.getLogger(__name__)


class CreditCheckResult:
    """Result of a credit pre-flight check."""

    def __init__(
        self, available: int, required: int, sufficient: bool
    ) -> None:
        self.available = available
        self.required = required
        self.sufficient = sufficient


class CreditManager:
    """Manages AI scan credits via the Medusa dashboard backend.

    Credits are tracked server-side in Supabase. The CLI calls
    the dashboard API to check balance and deduct credits.
    """

    def __init__(
        self,
        api_key: str,
        dashboard_url: str,
        timeout: int = 15,
    ) -> None:
        base = dashboard_url.rstrip("/")
        if "/api/" in base:
            base = base.rsplit("/api/", 1)[0]
        self._base = f"{base}/api/v1/credits"

        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )
        self._balance: int | None = None

    async def check_balance(self) -> int:
        """Fetch current credit balance from dashboard."""
        try:
            resp = await self._client.get(f"{self._base}/balance")
        except httpx.HTTPError as e:
            raise CreditError(
                f"Failed to check credit balance: {e}"
            ) from e

        if resp.status_code == 401:
            raise CreditError(
                "Invalid Medusa API key. Run 'medusa configure'."
            )

        if resp.status_code != 200:
            raise CreditError(
                f"Credit check failed ({resp.status_code})"
            )

        try:
            data = resp.json()
            self._balance = int(data.get("available", 0))
            return self._balance
        except (ValueError, KeyError) as e:
            raise CreditError(
                f"Invalid credit balance response: {e}"
            ) from e

    async def preflight(self, required: int) -> CreditCheckResult:
        """Pre-flight check: does the user have enough credits?"""
        try:
            resp = await self._client.post(
                f"{self._base}/check",
                json={"required": required},
            )
        except httpx.HTTPError as e:
            raise CreditError(
                f"Credit pre-flight failed: {e}"
            ) from e

        if resp.status_code == 401:
            raise CreditError(
                "Invalid Medusa API key. Run 'medusa configure'."
            )

        if resp.status_code != 200:
            raise CreditError(
                f"Credit pre-flight failed ({resp.status_code})"
            )

        try:
            data = resp.json()
            available = int(data.get("available", 0))
            sufficient = bool(data.get("sufficient", False))
            self._balance = available
            return CreditCheckResult(
                available=available,
                required=required,
                sufficient=sufficient,
            )
        except (ValueError, KeyError) as e:
            raise CreditError(
                f"Invalid credit pre-flight response: {e}"
            ) from e

    async def deduct(
        self,
        check_id: str,
        server_name: str,
        scan_id: str,
    ) -> bool:
        """Deduct 1 credit for an AI check execution.

        Returns True if successful, False if insufficient credits.
        Raises CreditError on network/API failures.
        """
        try:
            resp = await self._client.post(
                f"{self._base}/deduct",
                json={
                    "check_id": check_id,
                    "server_name": server_name,
                    "scan_id": scan_id,
                },
            )
        except httpx.HTTPError as e:
            raise CreditError(
                f"Credit deduction failed: {e}"
            ) from e

        if resp.status_code == 402:
            return False

        if resp.status_code == 401:
            raise CreditError(
                "Invalid Medusa API key. Run 'medusa configure'."
            )

        if resp.status_code != 200:
            raise CreditError(
                f"Credit deduction failed ({resp.status_code})"
            )

        try:
            data = resp.json()
            self._balance = int(data.get("remaining", 0))
            return bool(data.get("success", True))
        except (ValueError, KeyError):
            # Deduction succeeded but response is odd
            return True

    @property
    def remaining(self) -> int | None:
        """Last known credit balance, or None if unchecked."""
        return self._balance

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
