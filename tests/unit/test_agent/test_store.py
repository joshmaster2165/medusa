"""Tests for agent SQLite store."""

from __future__ import annotations

from medusa.agent.models import ProxyRegistration, ProxyState, TelemetryEvent
from medusa.agent.store import AgentStore


class TestStoreInit:
    """Tests for store initialization."""

    def test_create_store(self, tmp_path):
        db_path = tmp_path / "test.db"
        AgentStore(db_path=db_path)
        assert db_path.exists()

    def test_create_tables(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = AgentStore(db_path=db_path)
        # Tables exist if we can query them
        assert store.count_events() == 0
        assert store.list_proxies() == []
        assert store.get_state("nonexistent") == ""

    def test_db_path_property(self, tmp_path):
        db_path = tmp_path / "test.db"
        store = AgentStore(db_path=db_path)
        assert store.db_path == db_path


class TestStoreEvents:
    """Tests for event CRUD operations."""

    def _make_store(self, tmp_path):
        return AgentStore(db_path=tmp_path / "test.db")

    def test_insert_event(self, tmp_path):
        store = self._make_store(tmp_path)
        event = TelemetryEvent(
            direction="request",
            message_type="tools/call",
            tool_name="read_file",
            server_name="test",
            verdict="allow",
        )
        store.insert_event(event)
        assert store.count_events() == 1

    def test_insert_multiple_events(self, tmp_path):
        store = self._make_store(tmp_path)
        for i in range(5):
            event = TelemetryEvent(
                direction="request",
                verdict="allow",
                server_name=f"server-{i}",
            )
            store.insert_event(event)
        assert store.count_events() == 5

    def test_get_pending_events(self, tmp_path):
        store = self._make_store(tmp_path)
        for i in range(3):
            store.insert_event(TelemetryEvent(direction="request", verdict="allow"))

        pending = store.get_pending_events(limit=10)
        assert len(pending) == 3
        assert all(not e.uploaded for e in pending)

    def test_get_pending_events_limit(self, tmp_path):
        store = self._make_store(tmp_path)
        for _ in range(10):
            store.insert_event(TelemetryEvent(verdict="allow"))

        pending = store.get_pending_events(limit=3)
        assert len(pending) == 3

    def test_mark_events_uploaded(self, tmp_path):
        store = self._make_store(tmp_path)
        events = []
        for _ in range(3):
            e = TelemetryEvent(verdict="allow")
            store.insert_event(e)
            events.append(e)

        # Mark first 2 as uploaded
        marked = store.mark_events_uploaded([events[0].id, events[1].id])
        assert marked == 2

        pending = store.get_pending_events()
        assert len(pending) == 1
        assert pending[0].id == events[2].id

    def test_mark_empty_list(self, tmp_path):
        store = self._make_store(tmp_path)
        assert store.mark_events_uploaded([]) == 0

    def test_count_events_all(self, tmp_path):
        store = self._make_store(tmp_path)
        for _ in range(5):
            store.insert_event(TelemetryEvent(verdict="allow"))
        assert store.count_events() == 5

    def test_count_events_uploaded_filter(self, tmp_path):
        store = self._make_store(tmp_path)
        events = []
        for _ in range(4):
            e = TelemetryEvent(verdict="allow")
            store.insert_event(e)
            events.append(e)

        store.mark_events_uploaded([events[0].id])

        assert store.count_events(uploaded=True) == 1
        assert store.count_events(uploaded=False) == 3

    def test_duplicate_event_ignored(self, tmp_path):
        store = self._make_store(tmp_path)
        event = TelemetryEvent(verdict="allow")
        store.insert_event(event)
        store.insert_event(event)  # Same ID
        assert store.count_events() == 1


class TestStoreAgentState:
    """Tests for key-value agent state."""

    def _make_store(self, tmp_path):
        return AgentStore(db_path=tmp_path / "test.db")

    def test_set_and_get(self, tmp_path):
        store = self._make_store(tmp_path)
        store.set_state("foo", "bar")
        assert store.get_state("foo") == "bar"

    def test_get_default(self, tmp_path):
        store = self._make_store(tmp_path)
        assert store.get_state("nonexistent") == ""
        assert store.get_state("nonexistent", "default") == "default"

    def test_overwrite(self, tmp_path):
        store = self._make_store(tmp_path)
        store.set_state("key", "value1")
        store.set_state("key", "value2")
        assert store.get_state("key") == "value2"

    def test_get_all_state(self, tmp_path):
        store = self._make_store(tmp_path)
        store.set_state("a", "1")
        store.set_state("b", "2")
        store.set_state("c", "3")
        all_state = store.get_all_state()
        assert all_state == {"a": "1", "b": "2", "c": "3"}


class TestStoreProxyRegistry:
    """Tests for proxy process registration."""

    def _make_store(self, tmp_path):
        return AgentStore(db_path=tmp_path / "test.db")

    def test_register_proxy(self, tmp_path):
        store = self._make_store(tmp_path)
        proxy = ProxyRegistration(
            pid=12345,
            server_name="test-server",
            server_command="npx server",
            client_name="cursor",
        )
        store.register_proxy(proxy)

        proxies = store.list_proxies()
        assert len(proxies) == 1
        assert proxies[0].pid == 12345
        assert proxies[0].server_name == "test-server"

    def test_list_proxies_by_state(self, tmp_path):
        store = self._make_store(tmp_path)
        store.register_proxy(ProxyRegistration(pid=1, server_name="s1"))
        store.register_proxy(ProxyRegistration(pid=2, server_name="s2"))

        store.mark_proxy_dead(1)

        active = store.list_proxies(state=ProxyState.ACTIVE)
        dead = store.list_proxies(state=ProxyState.DEAD)
        assert len(active) == 1
        assert len(dead) == 1
        assert active[0].pid == 2
        assert dead[0].pid == 1

    def test_unregister_proxy(self, tmp_path):
        store = self._make_store(tmp_path)
        store.register_proxy(ProxyRegistration(pid=1, server_name="s1"))
        store.register_proxy(ProxyRegistration(pid=2, server_name="s2"))

        store.unregister_proxy(1)
        proxies = store.list_proxies()
        assert len(proxies) == 1
        assert proxies[0].pid == 2

    def test_heartbeat_proxy(self, tmp_path):
        store = self._make_store(tmp_path)
        proxy = ProxyRegistration(pid=1, server_name="s1")
        store.register_proxy(proxy)

        new_time = "2025-12-31T00:00:00Z"
        store.heartbeat_proxy(1, new_time)

        proxies = store.list_proxies()
        assert proxies[0].last_heartbeat == new_time

    def test_cleanup_dead_proxies(self, tmp_path):
        store = self._make_store(tmp_path)
        store.register_proxy(ProxyRegistration(pid=1, server_name="s1"))
        store.register_proxy(ProxyRegistration(pid=2, server_name="s2"))
        store.register_proxy(ProxyRegistration(pid=3, server_name="s3"))

        store.mark_proxy_dead(1)
        store.mark_proxy_dead(3)

        cleaned = store.cleanup_dead_proxies()
        assert cleaned == 2

        remaining = store.list_proxies()
        assert len(remaining) == 1
        assert remaining[0].pid == 2

    def test_register_replaces_existing_pid(self, tmp_path):
        store = self._make_store(tmp_path)
        store.register_proxy(ProxyRegistration(pid=1, server_name="old"))
        store.register_proxy(ProxyRegistration(pid=1, server_name="new"))

        proxies = store.list_proxies()
        assert len(proxies) == 1
        assert proxies[0].server_name == "new"
