"""Tests for health monitor."""

from __future__ import annotations

import os

from medusa.agent.health import HealthMonitor
from medusa.agent.models import ProxyRegistration
from medusa.agent.store import AgentStore


class TestHealthMonitor:
    """Tests for HealthMonitor."""

    def _make_monitor(self, tmp_path):
        store = AgentStore(db_path=tmp_path / "test.db")
        return HealthMonitor(store), store

    def test_check_all_no_proxies(self, tmp_path):
        monitor, store = self._make_monitor(tmp_path)
        result = monitor.check_all()
        assert result == {"alive": 0, "dead": 0, "cleaned": 0}

    def test_check_all_alive_proxy(self, tmp_path):
        monitor, store = self._make_monitor(tmp_path)

        # Register current process as a proxy (guaranteed alive)
        store.register_proxy(ProxyRegistration(pid=os.getpid(), server_name="test"))

        result = monitor.check_all()
        assert result["alive"] == 1
        assert result["dead"] == 0

    def test_check_all_dead_proxy(self, tmp_path):
        monitor, store = self._make_monitor(tmp_path)

        # Register a fake PID (guaranteed not running)
        store.register_proxy(ProxyRegistration(pid=9999999, server_name="dead-server"))

        result = monitor.check_all()
        assert result["alive"] == 0
        assert result["dead"] == 1
        assert result["cleaned"] == 1

        # Dead proxy should be cleaned up
        remaining = store.list_proxies()
        assert len(remaining) == 0

    def test_check_all_mixed(self, tmp_path):
        monitor, store = self._make_monitor(tmp_path)

        # Alive proxy
        store.register_proxy(ProxyRegistration(pid=os.getpid(), server_name="alive-server"))
        # Dead proxy
        store.register_proxy(ProxyRegistration(pid=9999999, server_name="dead-server"))

        result = monitor.check_all()
        assert result["alive"] == 1
        assert result["dead"] == 1

    def test_get_status_empty(self, tmp_path):
        monitor, store = self._make_monitor(tmp_path)
        status = monitor.get_status()
        assert status["total"] == 0
        assert status["alive"] == 0
        assert status["dead"] == 0
        assert status["proxies"] == []

    def test_get_status_with_proxies(self, tmp_path):
        monitor, store = self._make_monitor(tmp_path)

        store.register_proxy(
            ProxyRegistration(
                pid=os.getpid(),
                server_name="test-server",
                client_name="cursor",
            )
        )

        status = monitor.get_status()
        assert status["total"] == 1
        assert status["alive"] == 1
        assert len(status["proxies"]) == 1
        assert status["proxies"][0]["server_name"] == "test-server"
        assert status["proxies"][0]["state"] == "alive"
