"""Tests for gateway policy engine."""

from __future__ import annotations

from medusa.gateway.interceptor import Direction, MCPMessage, classify_message
from medusa.gateway.policy import (
    GatewayPolicy,
    PolicyEngine,
    PolicyResult,
    Verdict,
)

# ── Helper to build classified messages ────────────────────────────────


def _tool_call_message(
    tool_name: str = "read_file",
    arguments: dict | None = None,
    msg_id: int = 1,
) -> MCPMessage:
    """Build a classified tool call message."""
    raw = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": msg_id,
        "params": {
            "name": tool_name,
            "arguments": arguments or {},
        },
    }
    return classify_message(raw, Direction.CLIENT_TO_SERVER)


def _tools_list_message(msg_id: int = 1) -> MCPMessage:
    raw = {"jsonrpc": "2.0", "method": "tools/list", "id": msg_id}
    return classify_message(raw, Direction.CLIENT_TO_SERVER)


def _response_message(result: dict | None = None, msg_id: int = 1) -> MCPMessage:
    raw = {"jsonrpc": "2.0", "id": msg_id, "result": result or {}}
    return classify_message(raw, Direction.SERVER_TO_CLIENT)


# ── Verdict enum tests ─────────────────────────────────────────────────


class TestVerdict:
    def test_values(self):
        assert Verdict.ALLOW == "allow"
        assert Verdict.BLOCK == "block"
        assert Verdict.COACH == "coach"


# ── GatewayPolicy defaults ────────────────────────────────────────────


class TestGatewayPolicy:
    def test_defaults(self):
        policy = GatewayPolicy()
        assert policy.blocked_servers == []
        assert policy.allowed_servers is None
        assert policy.blocked_tools == []
        assert policy.blocked_tool_patterns == []
        assert policy.max_calls_per_minute == 0
        assert policy.block_secrets is True
        assert policy.block_pii is False
        assert policy.scan_responses is True
        assert policy.scan_code is False
        assert policy.coaching_enabled is True


# ── PolicyEngine basic tests ──────────────────────────────────────────


class TestPolicyEngineBasic:
    """Tests for basic PolicyEngine behavior."""

    def test_default_policy_allows_everything(self):
        engine = PolicyEngine(GatewayPolicy(block_secrets=False))
        msg = _tool_call_message("read_file")
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.ALLOW

    def test_tools_list_always_allowed(self):
        engine = PolicyEngine(GatewayPolicy(block_secrets=False))
        msg = _tools_list_message()
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.ALLOW

    def test_response_allowed_by_default(self):
        engine = PolicyEngine(GatewayPolicy(block_secrets=False))
        msg = _response_message({"tools": []})
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.ALLOW


# ── Server blocklist tests ────────────────────────────────────────────


class TestServerBlocklist:
    def test_block_server(self):
        policy = GatewayPolicy(
            blocked_servers=["malicious-server"],
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("some_tool")
        result = engine.evaluate(msg, server_name="malicious-server")
        assert result.verdict == Verdict.COACH  # coaching enabled by default
        assert "blocked" in result.reason.lower()

    def test_block_server_partial_match(self):
        policy = GatewayPolicy(
            blocked_servers=["malicious"],
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("some_tool")
        result = engine.evaluate(msg, server_name="super-malicious-server")
        assert result.verdict == Verdict.COACH

    def test_block_server_case_insensitive(self):
        policy = GatewayPolicy(
            blocked_servers=["MALICIOUS"],
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("some_tool")
        result = engine.evaluate(msg, server_name="malicious-server")
        assert result.verdict == Verdict.COACH

    def test_allowed_server_passes(self):
        policy = GatewayPolicy(
            blocked_servers=["malicious-server"],
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("some_tool")
        result = engine.evaluate(msg, server_name="safe-server")
        assert result.verdict == Verdict.ALLOW


# ── Server allowlist tests ────────────────────────────────────────────


class TestServerAllowlist:
    def test_allowlist_blocks_unlisted(self):
        policy = GatewayPolicy(
            allowed_servers=["approved-server"],
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("some_tool")
        result = engine.evaluate(msg, server_name="unknown-server")
        assert result.verdict == Verdict.COACH
        assert "allowlist" in result.reason.lower()

    def test_allowlist_allows_listed(self):
        policy = GatewayPolicy(
            allowed_servers=["approved-server"],
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("some_tool")
        result = engine.evaluate(msg, server_name="approved-server")
        assert result.verdict == Verdict.ALLOW

    def test_no_allowlist_allows_all(self):
        policy = GatewayPolicy(
            allowed_servers=None,
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("some_tool")
        result = engine.evaluate(msg, server_name="any-server")
        assert result.verdict == Verdict.ALLOW


# ── Tool blocklist tests ──────────────────────────────────────────────


class TestToolBlocklist:
    def test_block_exact_tool(self):
        policy = GatewayPolicy(
            blocked_tools=["execute_command"],
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("execute_command")
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.COACH
        assert "blocked" in result.reason.lower()

    def test_allow_non_blocked_tool(self):
        policy = GatewayPolicy(
            blocked_tools=["execute_command"],
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("read_file")
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.ALLOW

    def test_block_tool_pattern(self):
        policy = GatewayPolicy(
            blocked_tool_patterns=[r"^exec.*", r"^run_.*"],
            block_secrets=False,
        )
        engine = PolicyEngine(policy)

        msg1 = _tool_call_message("execute_shell")
        result1 = engine.evaluate(msg1)
        assert result1.verdict == Verdict.COACH

        msg2 = _tool_call_message("run_command")
        result2 = engine.evaluate(msg2)
        assert result2.verdict == Verdict.COACH

    def test_pattern_case_insensitive(self):
        policy = GatewayPolicy(
            blocked_tool_patterns=[r"execute"],
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("EXECUTE_COMMAND")
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.COACH


# ── Rate limiting tests ───────────────────────────────────────────────


class TestRateLimiting:
    def test_no_rate_limit(self):
        policy = GatewayPolicy(max_calls_per_minute=0, block_secrets=False)
        engine = PolicyEngine(policy)

        for i in range(100):
            msg = _tool_call_message("fast_tool", msg_id=i)
            result = engine.evaluate(msg)
            assert result.verdict == Verdict.ALLOW

    def test_rate_limit_triggers(self):
        policy = GatewayPolicy(max_calls_per_minute=3, block_secrets=False)
        engine = PolicyEngine(policy)

        results = []
        for i in range(5):
            msg = _tool_call_message("limited_tool", msg_id=i)
            results.append(engine.evaluate(msg))

        # First 3 should pass, 4th and 5th should be blocked
        assert results[0].verdict == Verdict.ALLOW
        assert results[1].verdict == Verdict.ALLOW
        assert results[2].verdict == Verdict.ALLOW
        assert results[3].verdict == Verdict.COACH
        assert "rate limit" in results[3].reason.lower()

    def test_rate_limit_per_tool(self):
        """Different tools have separate rate limit counters."""
        policy = GatewayPolicy(max_calls_per_minute=2, block_secrets=False)
        engine = PolicyEngine(policy)

        # 2 calls for tool_a: should pass
        for i in range(2):
            msg = _tool_call_message("tool_a", msg_id=i)
            result = engine.evaluate(msg)
            assert result.verdict == Verdict.ALLOW

        # 2 calls for tool_b: should also pass (separate counter)
        for i in range(2):
            msg = _tool_call_message("tool_b", msg_id=10 + i)
            result = engine.evaluate(msg)
            assert result.verdict == Verdict.ALLOW

        # 3rd call for tool_a: should be blocked
        msg = _tool_call_message("tool_a", msg_id=99)
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.COACH

    def test_non_tool_calls_not_rate_limited(self):
        policy = GatewayPolicy(max_calls_per_minute=1, block_secrets=False)
        engine = PolicyEngine(policy)

        # tools/list requests should not be rate limited
        for i in range(10):
            msg = _tools_list_message(msg_id=i)
            result = engine.evaluate(msg)
            assert result.verdict == Verdict.ALLOW


# ── DLP integration tests ─────────────────────────────────────────────


class TestDLPIntegration:
    def test_detect_secret_in_tool_args(self):
        policy = GatewayPolicy(block_secrets=True)
        engine = PolicyEngine(policy)

        msg = _tool_call_message(
            "write_file",
            arguments={"content": "aws_key=AKIAIOSFODNN7EXAMPLE"},
        )
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.COACH
        assert "sensitive" in result.reason.lower() or "secret" in result.reason.lower()

    def test_detect_pii_when_enabled(self):
        policy = GatewayPolicy(block_pii=True, block_secrets=False)
        engine = PolicyEngine(policy)

        msg = _tool_call_message(
            "send_email",
            arguments={"body": "SSN is 123-45-6789"},
        )
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.COACH

    def test_no_pii_when_disabled(self):
        policy = GatewayPolicy(block_pii=False, block_secrets=False)
        engine = PolicyEngine(policy)

        msg = _tool_call_message(
            "send_email",
            arguments={"body": "SSN is 123-45-6789"},
        )
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.ALLOW

    def test_scan_response_dlp(self):
        policy = GatewayPolicy(block_pii=True, scan_responses=True, block_secrets=False)
        engine = PolicyEngine(policy)

        raw = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "SSN: 123-45-6789"}],
            },
        }
        msg = classify_message(raw, Direction.SERVER_TO_CLIENT)
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.COACH

    def test_skip_response_scan_when_disabled(self):
        policy = GatewayPolicy(block_pii=True, scan_responses=False, block_secrets=False)
        engine = PolicyEngine(policy)

        raw = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "SSN: 123-45-6789"}],
            },
        }
        msg = classify_message(raw, Direction.SERVER_TO_CLIENT)
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.ALLOW


# ── Coaching vs Block mode ────────────────────────────────────────────


class TestCoachingMode:
    def test_coaching_enabled_returns_coach(self):
        policy = GatewayPolicy(
            blocked_tools=["dangerous_tool"],
            coaching_enabled=True,
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("dangerous_tool")
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.COACH
        assert result.coaching_message is not None

    def test_coaching_disabled_returns_block(self):
        policy = GatewayPolicy(
            blocked_tools=["dangerous_tool"],
            coaching_enabled=False,
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("dangerous_tool")
        result = engine.evaluate(msg)
        assert result.verdict == Verdict.BLOCK
        assert result.coaching_message is None


# ── Priority order tests ──────────────────────────────────────────────


class TestPriorityOrder:
    """Verify that checks run in the correct priority order."""

    def test_server_block_takes_priority_over_tool_block(self):
        policy = GatewayPolicy(
            blocked_servers=["bad-server"],
            blocked_tools=["safe_tool"],
            block_secrets=False,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message("safe_tool")
        result = engine.evaluate(msg, server_name="bad-server")
        assert result.rule_name == "server_blocked"

    def test_tool_block_takes_priority_over_dlp(self):
        policy = GatewayPolicy(
            blocked_tools=["write_file"],
            block_secrets=True,
        )
        engine = PolicyEngine(policy)
        msg = _tool_call_message(
            "write_file",
            arguments={"content": "AKIAIOSFODNN7EXAMPLE"},
        )
        result = engine.evaluate(msg)
        assert result.rule_name == "tool_blocked"


# ── PolicyResult tests ────────────────────────────────────────────────


class TestPolicyResult:
    def test_allow_result(self):
        result = PolicyResult(verdict=Verdict.ALLOW)
        assert result.verdict == Verdict.ALLOW
        assert result.rule_name == ""
        assert result.reason == ""
        assert result.coaching_message is None

    def test_full_result(self):
        result = PolicyResult(
            verdict=Verdict.COACH,
            rule_name="test_rule",
            reason="test reason",
            coaching_message="try this instead",
        )
        assert result.verdict == Verdict.COACH
        assert result.rule_name == "test_rule"
        assert result.reason == "test reason"
        assert result.coaching_message == "try this instead"
