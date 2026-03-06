"""Telemetry manager for uploading gateway events to the dashboard.

Reads pending events from the shared SQLite store and batch-uploads
them to the Supabase backend via the gateway-events Edge Function.
"""

from __future__ import annotations

import logging

import httpx

from medusa.agent.models import AgentConfig, TelemetryEvent
from medusa.agent.store import AgentStore

logger = logging.getLogger(__name__)


class TelemetryManager:
    """Batches and uploads telemetry events to Supabase.

    Called periodically by the daemon's telemetry loop.
    """

    def __init__(
        self,
        config: AgentConfig,
        store: AgentStore,
        timeout: int = 30,
    ) -> None:
        self._config = config
        self._store = store
        self._timeout = timeout
        self._endpoint = f"{config.supabase_url.rstrip('/')}/functions/v1/gateway-events"

    async def upload_batch(self) -> dict:
        """Upload a batch of pending events.

        Returns a summary dict: {uploaded: int, errors: int}.
        """
        events = self._store.get_pending_events(limit=self._config.telemetry_batch_size)

        if not events:
            return {"uploaded": 0, "errors": 0}

        # Serialize events for upload
        payload = {
            "agent_id": self._config.agent_id,
            "customer_id": self._config.customer_id,
            "hostname": self._config.hostname,
            "events": [self._serialize_event(e) for e in events],
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    self._endpoint,
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {self._config.api_key}",
                        "Content-Type": "application/json",
                    },
                )

            if resp.status_code == 200:
                event_ids = [e.id for e in events]
                marked = self._store.mark_events_uploaded(event_ids)
                logger.info("Uploaded %d events to dashboard", marked)
                return {"uploaded": marked, "errors": 0}
            else:
                logger.warning(
                    "Telemetry upload failed: %d %s",
                    resp.status_code,
                    resp.text[:200],
                )
                return {"uploaded": 0, "errors": len(events)}

        except httpx.HTTPError as e:
            logger.warning("Telemetry upload error: %s", e)
            return {"uploaded": 0, "errors": len(events)}

    @staticmethod
    def _serialize_event(event: TelemetryEvent) -> dict:
        """Serialize an event for JSON upload."""
        return {
            "id": event.id,
            "timestamp": event.timestamp,
            "direction": event.direction,
            "message_type": event.message_type,
            "method": event.method,
            "tool_name": event.tool_name,
            "server_name": event.server_name,
            "verdict": event.verdict,
            "rule_name": event.rule_name,
            "reason": event.reason,
        }
