"""Health monitor for gateway proxy processes.

Checks that registered proxy processes are still alive and
marks dead entries for cleanup.
"""

from __future__ import annotations

import logging

from medusa.agent.models import ProxyState
from medusa.agent.platform.common import is_process_alive
from medusa.agent.store import AgentStore

logger = logging.getLogger(__name__)


class HealthMonitor:
    """Monitors proxy process liveness via PID checks.

    Called periodically by the daemon's health loop.
    """

    def __init__(self, store: AgentStore) -> None:
        self._store = store

    def check_all(self) -> dict:
        """Check all registered proxies and mark dead ones.

        Returns summary: {alive: int, dead: int, cleaned: int}.
        """
        proxies = self._store.list_proxies(state=ProxyState.ACTIVE)
        alive = 0
        dead = 0

        for proxy in proxies:
            if is_process_alive(proxy.pid):
                alive += 1
            else:
                dead += 1
                self._store.mark_proxy_dead(proxy.pid)
                logger.info(
                    "Proxy for '%s' (pid=%d) is dead, marking for cleanup",
                    proxy.server_name,
                    proxy.pid,
                )

        # Clean up dead entries
        cleaned = self._store.cleanup_dead_proxies()

        if dead > 0:
            logger.info(
                "Health check: %d alive, %d dead (%d cleaned)",
                alive,
                dead,
                cleaned,
            )

        return {"alive": alive, "dead": dead, "cleaned": cleaned}

    def get_status(self) -> dict:
        """Get a health status summary.

        Returns dict with counts and per-proxy details.
        """
        all_proxies = self._store.list_proxies()
        alive = 0
        dead = 0
        details = []

        for proxy in all_proxies:
            is_alive = is_process_alive(proxy.pid)
            if is_alive:
                alive += 1
            else:
                dead += 1

            details.append(
                {
                    "pid": proxy.pid,
                    "server_name": proxy.server_name,
                    "client_name": proxy.client_name,
                    "started_at": proxy.started_at,
                    "last_heartbeat": proxy.last_heartbeat,
                    "state": "alive" if is_alive else "dead",
                }
            )

        return {
            "total": len(all_proxies),
            "alive": alive,
            "dead": dead,
            "proxies": details,
        }
