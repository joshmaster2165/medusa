"""Policy sync manager — fetches gateway policies from the dashboard.

Periodically polls the Supabase backend for the latest gateway
policy and writes it to ~/.medusa/gateway-policy.yaml so that
proxy processes can load it on startup.
"""

from __future__ import annotations

import logging

import httpx
import yaml

from medusa.agent.models import GATEWAY_POLICY_PATH, AgentConfig

logger = logging.getLogger(__name__)


class PolicySyncManager:
    """Fetches gateway policy from the Medusa dashboard.

    Writes to ~/.medusa/gateway-policy.yaml which is read
    by gateway proxy processes via the PolicyEngine.
    """

    def __init__(
        self,
        config: AgentConfig,
        timeout: int = 15,
    ) -> None:
        self._config = config
        self._timeout = timeout
        self._endpoint = f"{config.supabase_url.rstrip('/')}/functions/v1/gateway-policy"
        self._last_etag: str = ""

    async def sync(self) -> dict:
        """Fetch latest policy from dashboard and write to disk.

        Returns a summary dict: {updated: bool, error: str | None}.
        """
        try:
            headers = {
                "Authorization": f"Bearer {self._config.api_key}",
                "Content-Type": "application/json",
            }
            if self._last_etag:
                headers["If-None-Match"] = self._last_etag

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    self._endpoint,
                    params={"customer_id": self._config.customer_id},
                    headers=headers,
                )

            if resp.status_code == 304:
                # No changes
                return {"updated": False, "error": None}

            if resp.status_code == 200:
                policy_data = resp.json()
                etag = resp.headers.get("ETag", "")

                # Write policy to YAML
                self._write_policy(policy_data)
                self._last_etag = etag

                logger.info("Policy synced from dashboard")
                return {"updated": True, "error": None}

            if resp.status_code == 401:
                return {"updated": False, "error": "Invalid API key"}

            if resp.status_code == 404:
                # No policy configured for this customer yet
                return {"updated": False, "error": None}

            return {
                "updated": False,
                "error": f"HTTP {resp.status_code}",
            }

        except httpx.HTTPError as e:
            logger.warning("Policy sync error: %s", e)
            return {"updated": False, "error": str(e)}

    def _write_policy(self, policy_data: dict) -> None:
        """Write policy data to ~/.medusa/gateway-policy.yaml."""
        GATEWAY_POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
        GATEWAY_POLICY_PATH.write_text(yaml.dump(policy_data, default_flow_style=False))

    @staticmethod
    def load_local_policy() -> dict | None:
        """Load the locally cached policy, or None if not found."""
        if not GATEWAY_POLICY_PATH.exists():
            return None
        try:
            return yaml.safe_load(GATEWAY_POLICY_PATH.read_text())
        except (yaml.YAMLError, OSError):
            return None
