"""SQLite persistence for the Medusa Agent.

Shared between gateway proxy processes (writers) and the agent
daemon (reader/writer).  Uses WAL mode for concurrent access.

Tables:
- events:          Telemetry events from proxy processes
- agent_state:     Agent configuration/status key-value pairs
- proxy_registry:  Active proxy process registrations
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from medusa.agent.models import (
    AGENT_DB_PATH,
    ProxyRegistration,
    ProxyState,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


class AgentStore:
    """SQLite store shared between proxy processes and the agent daemon.

    Uses WAL mode for safe concurrent reads/writes from multiple
    processes (proxy writers + daemon reader).
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path else AGENT_DB_PATH
        self._ensure_dir()
        self._init_db()

    def _ensure_dir(self) -> None:
        """Create ~/.medusa/ if it doesn't exist."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode = WAL;
                PRAGMA busy_timeout = 5000;

                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT DEFAULT '',
                    customer_id TEXT DEFAULT '',
                    direction TEXT DEFAULT '',
                    message_type TEXT DEFAULT '',
                    method TEXT,
                    tool_name TEXT,
                    server_name TEXT DEFAULT '',
                    verdict TEXT DEFAULT '',
                    rule_name TEXT DEFAULT '',
                    reason TEXT DEFAULT '',
                    uploaded INTEGER DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_events_uploaded
                    ON events(uploaded) WHERE uploaded = 0;

                CREATE INDEX IF NOT EXISTS idx_events_timestamp
                    ON events(timestamp);

                CREATE TABLE IF NOT EXISTS agent_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS proxy_registry (
                    pid INTEGER PRIMARY KEY,
                    server_name TEXT NOT NULL,
                    server_command TEXT DEFAULT '',
                    client_name TEXT DEFAULT '',
                    started_at TEXT NOT NULL,
                    last_heartbeat TEXT NOT NULL,
                    state TEXT DEFAULT 'active'
                );
                """
            )

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Create a connection with WAL mode and row factory."""
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Events ───────────────────────────────────────────────────────

    def insert_event(self, event: TelemetryEvent) -> None:
        """Insert a telemetry event (called by proxy processes)."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO events
                    (id, timestamp, agent_id, customer_id, direction,
                     message_type, method, tool_name, server_name,
                     verdict, rule_name, reason, uploaded)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    event.id,
                    event.timestamp,
                    event.agent_id,
                    event.customer_id,
                    event.direction,
                    event.message_type,
                    event.method,
                    event.tool_name,
                    event.server_name,
                    event.verdict,
                    event.rule_name,
                    event.reason,
                ),
            )

    def get_pending_events(self, limit: int = 100) -> list[TelemetryEvent]:
        """Fetch events not yet uploaded (called by daemon)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE uploaded = 0 ORDER BY timestamp LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def mark_events_uploaded(self, event_ids: list[str]) -> int:
        """Mark events as uploaded. Returns count marked."""
        if not event_ids:
            return 0
        with self._connect() as conn:
            placeholders = ",".join("?" * len(event_ids))
            cursor = conn.execute(
                f"UPDATE events SET uploaded = 1 WHERE id IN ({placeholders})",
                event_ids,
            )
            return cursor.rowcount

    def count_events(self, uploaded: bool | None = None) -> int:
        """Count events, optionally filtered by upload status."""
        with self._connect() as conn:
            if uploaded is None:
                row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            else:
                row = conn.execute(
                    "SELECT COUNT(*) FROM events WHERE uploaded = ?",
                    (int(uploaded),),
                ).fetchone()
            return row[0] if row else 0

    def purge_old_events(self, older_than_days: int = 7) -> int:
        """Delete uploaded events older than N days."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                DELETE FROM events
                WHERE uploaded = 1
                  AND datetime(timestamp) < datetime('now', ?)
                """,
                (f"-{older_than_days} days",),
            )
            return cursor.rowcount

    # ── Agent State (key-value) ──────────────────────────────────────

    def get_state(self, key: str, default: str = "") -> str:
        """Get an agent state value by key."""
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM agent_state WHERE key = ?", (key,)).fetchone()
            return row[0] if row else default

    def set_state(self, key: str, value: str) -> None:
        """Set an agent state value."""
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO agent_state (key, value) VALUES (?, ?)",
                (key, value),
            )

    def get_all_state(self) -> dict[str, str]:
        """Get all agent state key-value pairs."""
        with self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM agent_state").fetchall()
            return {r[0]: r[1] for r in rows}

    # ── Proxy Registry ───────────────────────────────────────────────

    def register_proxy(self, proxy: ProxyRegistration) -> None:
        """Register a proxy process (called by proxy on startup)."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO proxy_registry
                    (pid, server_name, server_command, client_name,
                     started_at, last_heartbeat, state)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proxy.pid,
                    proxy.server_name,
                    proxy.server_command,
                    proxy.client_name,
                    proxy.started_at,
                    proxy.last_heartbeat,
                    proxy.state.value,
                ),
            )

    def heartbeat_proxy(self, pid: int, heartbeat_time: str) -> None:
        """Update proxy heartbeat timestamp."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE proxy_registry SET last_heartbeat = ? WHERE pid = ?",
                (heartbeat_time, pid),
            )

    def unregister_proxy(self, pid: int) -> None:
        """Remove a proxy from the registry."""
        with self._connect() as conn:
            conn.execute("DELETE FROM proxy_registry WHERE pid = ?", (pid,))

    def list_proxies(self, state: ProxyState | None = None) -> list[ProxyRegistration]:
        """List registered proxies, optionally filtered by state."""
        with self._connect() as conn:
            if state:
                rows = conn.execute(
                    "SELECT * FROM proxy_registry WHERE state = ?",
                    (state.value,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM proxy_registry").fetchall()
        return [self._row_to_proxy(r) for r in rows]

    def mark_proxy_dead(self, pid: int) -> None:
        """Mark a proxy as dead (its process is no longer running)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE proxy_registry SET state = ? WHERE pid = ?",
                (ProxyState.DEAD.value, pid),
            )

    def cleanup_dead_proxies(self) -> int:
        """Remove all dead proxy entries. Returns count removed."""
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM proxy_registry WHERE state = ?",
                (ProxyState.DEAD.value,),
            )
            return cursor.rowcount

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> TelemetryEvent:
        return TelemetryEvent(
            id=row["id"],
            timestamp=row["timestamp"],
            agent_id=row["agent_id"],
            customer_id=row["customer_id"],
            direction=row["direction"],
            message_type=row["message_type"],
            method=row["method"],
            tool_name=row["tool_name"],
            server_name=row["server_name"],
            verdict=row["verdict"],
            rule_name=row["rule_name"],
            reason=row["reason"],
            uploaded=bool(row["uploaded"]),
        )

    @staticmethod
    def _row_to_proxy(row: sqlite3.Row) -> ProxyRegistration:
        return ProxyRegistration(
            pid=row["pid"],
            server_name=row["server_name"],
            server_command=row["server_command"],
            client_name=row["client_name"],
            started_at=row["started_at"],
            last_heartbeat=row["last_heartbeat"],
            state=ProxyState(row["state"]),
        )

    @property
    def db_path(self) -> Path:
        """Path to the SQLite database file."""
        return self._db_path

    def close(self) -> None:
        """No persistent connection to close (context-managed)."""
        pass
