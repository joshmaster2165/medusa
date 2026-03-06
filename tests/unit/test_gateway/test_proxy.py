"""Tests for gateway stdio proxy."""

from __future__ import annotations

from medusa.gateway.interceptor import Direction, classify_message
from medusa.gateway.policy import GatewayPolicy, PolicyEngine, PolicyResult, Verdict
from medusa.gateway.proxy import AuditEvent, ProxyStats, StdioGatewayProxy

# ── AuditEvent tests ──────────────────────────────────────────────────


class TestAuditEvent:
    def test_create_audit_event(self):
        event = AuditEvent(
            timestamp="2025-01-01T00:00:00Z",
            direction="request",
            message_type="tools/call",
            method="tools/call",
            tool_name="read_file",
            verdict="block",
            rule_name="tool_blocked",
            reason="Blocked by policy",
            server_name="test-server",
        )
        assert event.direction == "request"
        assert event.tool_name == "read_file"
        assert event.verdict == "block"


# ── ProxyStats tests ──────────────────────────────────────────────────


class TestProxyStats:
    def test_default_stats(self):
        stats = ProxyStats()
        assert stats.messages_total == 0
        assert stats.messages_allowed == 0
        assert stats.messages_blocked == 0
        assert stats.messages_coached == 0
        assert stats.start_time == 0.0
        assert stats.audit_log == []

    def test_stats_mutable(self):
        stats = ProxyStats()
        stats.messages_total = 10
        stats.messages_allowed = 7
        stats.messages_blocked = 2
        stats.messages_coached = 1
        assert stats.messages_total == 10


# ── StdioGatewayProxy init tests ─────────────────────────────────────


class TestStdioGatewayProxyInit:
    def test_init(self):
        policy = GatewayPolicy(block_secrets=False)
        engine = PolicyEngine(policy)
        proxy = StdioGatewayProxy(
            server_command=["npx", "server"],
            policy_engine=engine,
            server_name="test-server",
        )
        assert proxy.stats.messages_total == 0

    def test_init_default_name(self):
        policy = GatewayPolicy(block_secrets=False)
        engine = PolicyEngine(policy)
        proxy = StdioGatewayProxy(
            server_command=["npx", "-y", "@server/foo"],
            policy_engine=engine,
        )
        # Server name should be derived from command
        assert proxy._server_name == "npx -y"

    def test_init_audit_disabled(self):
        policy = GatewayPolicy(block_secrets=False)
        engine = PolicyEngine(policy)
        proxy = StdioGatewayProxy(
            server_command=["npx", "server"],
            policy_engine=engine,
            audit=False,
        )
        assert proxy._audit is False


# ── StdioGatewayProxy._record tests ──────────────────────────────────


class TestProxyRecord:
    """Tests for the _record method (stats + audit log)."""

    def setup_method(self):
        policy = GatewayPolicy(block_secrets=False)
        engine = PolicyEngine(policy)
        self.proxy = StdioGatewayProxy(
            server_command=["test"],
            policy_engine=engine,
            server_name="test",
        )

    def test_record_allow(self):
        raw = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        result = PolicyResult(verdict=Verdict.ALLOW)

        self.proxy._record(msg, result)

        assert self.proxy.stats.messages_total == 1
        assert self.proxy.stats.messages_allowed == 1
        assert self.proxy.stats.messages_blocked == 0
        assert len(self.proxy.stats.audit_log) == 0  # ALLOW not logged

    def test_record_block(self):
        raw = {"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": "evil"}}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        result = PolicyResult(
            verdict=Verdict.BLOCK,
            rule_name="test_block",
            reason="test reason",
        )

        self.proxy._record(msg, result)

        assert self.proxy.stats.messages_total == 1
        assert self.proxy.stats.messages_blocked == 1
        assert len(self.proxy.stats.audit_log) == 1
        event = self.proxy.stats.audit_log[0]
        assert event.verdict == "block"
        assert event.rule_name == "test_block"

    def test_record_coach(self):
        raw = {"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": "risky"}}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        result = PolicyResult(
            verdict=Verdict.COACH,
            rule_name="test_coach",
            reason="try something else",
            coaching_message="suggestion",
        )

        self.proxy._record(msg, result)

        assert self.proxy.stats.messages_total == 1
        assert self.proxy.stats.messages_coached == 1
        assert len(self.proxy.stats.audit_log) == 1

    def test_record_audit_disabled(self):
        policy = GatewayPolicy(block_secrets=False)
        engine = PolicyEngine(policy)
        proxy = StdioGatewayProxy(
            server_command=["test"],
            policy_engine=engine,
            server_name="test",
            audit=False,
        )

        raw = {"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": "evil"}}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        result = PolicyResult(
            verdict=Verdict.BLOCK,
            rule_name="test_block",
            reason="blocked",
        )

        proxy._record(msg, result)

        assert proxy.stats.messages_blocked == 1
        assert len(proxy.stats.audit_log) == 0  # Audit disabled

    def test_record_multiple(self):
        for i in range(5):
            raw = {"jsonrpc": "2.0", "method": "tools/list", "id": i}
            msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
            result = PolicyResult(verdict=Verdict.ALLOW)
            self.proxy._record(msg, result)

        raw = {"jsonrpc": "2.0", "method": "tools/call", "id": 99, "params": {"name": "bad"}}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        result = PolicyResult(verdict=Verdict.BLOCK, rule_name="r", reason="r")
        self.proxy._record(msg, result)

        assert self.proxy.stats.messages_total == 6
        assert self.proxy.stats.messages_allowed == 5
        assert self.proxy.stats.messages_blocked == 1
