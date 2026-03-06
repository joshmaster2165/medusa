"""Policy engine for MCP gateway traffic.

Evaluates JSON-RPC messages against configurable rules and returns
a verdict: ALLOW, BLOCK, or COACH (block + send feedback to LLM).
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum

from medusa.gateway.dlp import DLPCategory, DLPScanner
from medusa.gateway.interceptor import Direction, MCPMessage, MessageType

logger = logging.getLogger(__name__)


class Verdict(StrEnum):
    """Gateway verdict for a message."""

    ALLOW = "allow"
    BLOCK = "block"
    COACH = "coach"  # Block + coaching feedback for the LLM


@dataclass
class PolicyResult:
    """Result of evaluating a message against the policy engine."""

    verdict: Verdict
    rule_name: str = ""
    reason: str = ""
    coaching_message: str | None = None


@dataclass
class GatewayPolicy:
    """Configurable gateway policy.

    Loaded from ~/.medusa/gateway-policy.yaml or supplied
    programmatically in tests.
    """

    # Server-level controls
    blocked_servers: list[str] = field(default_factory=list)
    allowed_servers: list[str] | None = None  # None = allow all

    # Tool-level controls
    blocked_tools: list[str] = field(default_factory=list)
    blocked_tool_patterns: list[str] = field(default_factory=list)

    # Rate limiting
    max_calls_per_minute: int = 0  # 0 = no limit

    # DLP
    block_secrets: bool = True
    block_pii: bool = False
    scan_responses: bool = True
    scan_code: bool = False

    # Coaching
    coaching_enabled: bool = True


class PolicyEngine:
    """Evaluates MCP messages against a GatewayPolicy.

    Designed for hot-path execution: all checks are synchronous
    pattern matching or counter lookups (no I/O, no await).
    """

    def __init__(self, policy: GatewayPolicy) -> None:
        self._policy = policy
        self._dlp = DLPScanner(
            scan_secrets=policy.block_secrets,
            scan_pii=policy.block_pii,
            scan_code=policy.scan_code,
        )
        # Rate limiting state: tool_name → list of timestamps
        self._call_times: dict[str, list[float]] = defaultdict(list)
        # Compiled tool patterns
        self._tool_patterns = [re.compile(p, re.IGNORECASE) for p in policy.blocked_tool_patterns]

    @property
    def policy(self) -> GatewayPolicy:
        return self._policy

    def evaluate(
        self,
        message: MCPMessage,
        server_name: str = "",
    ) -> PolicyResult:
        """Evaluate a message and return a verdict.

        Checks are applied in priority order (most critical first):
        1. Server blocklist
        2. Tool blocklist / patterns
        3. Rate limiting
        4. DLP inspection
        """
        # ── 1. Server blocklist ──
        if server_name and self._policy.blocked_servers:
            lower_name = server_name.lower()
            for blocked in self._policy.blocked_servers:
                if blocked.lower() in lower_name:
                    return self._block_or_coach(
                        rule_name="server_blocked",
                        reason=f"Server '{server_name}' is blocked by policy.",
                        suggestion="Use an approved MCP server instead.",
                    )

        # ── 2. Server allowlist ──
        if (
            server_name
            and self._policy.allowed_servers is not None
            and server_name not in self._policy.allowed_servers
        ):
            return self._block_or_coach(
                rule_name="server_not_allowed",
                reason=f"Server '{server_name}' is not on the allowlist.",
                suggestion="Contact your administrator to approve this server.",
            )

        # ── 3. Tool blocklist ──
        if message.message_type == MessageType.TOOL_CALL and message.tool_name:
            tool = message.tool_name

            # Exact match
            if tool in self._policy.blocked_tools:
                return self._block_or_coach(
                    rule_name="tool_blocked",
                    reason=f"Tool '{tool}' is blocked by policy.",
                    suggestion=f"The tool '{tool}' is not allowed. Try a different approach.",
                )

            # Pattern match
            for pattern in self._tool_patterns:
                if pattern.search(tool):
                    return self._block_or_coach(
                        rule_name="tool_pattern_blocked",
                        reason=f"Tool '{tool}' matches blocked pattern.",
                        suggestion="This type of tool is restricted. Use an alternative.",
                    )

        # ── 4. Rate limiting ──
        if self._policy.max_calls_per_minute > 0 and message.message_type == MessageType.TOOL_CALL:
            tool = message.tool_name or "__any__"
            now = time.monotonic()
            window = 60.0

            # Prune old entries
            times = self._call_times[tool]
            self._call_times[tool] = [t for t in times if now - t < window]

            if len(self._call_times[tool]) >= self._policy.max_calls_per_minute:
                return self._block_or_coach(
                    rule_name="rate_limit",
                    reason=f"Rate limit exceeded: {self._policy.max_calls_per_minute} calls/min.",
                    suggestion="Wait a moment before retrying this tool call.",
                )

            self._call_times[tool].append(now)

        # ── 5. DLP inspection ──
        should_scan = message.direction == Direction.CLIENT_TO_SERVER or (
            message.direction == Direction.SERVER_TO_CLIENT and self._policy.scan_responses
        )
        if should_scan:
            dlp_findings = self._dlp.scan_message_payload(message.raw)
            if dlp_findings:
                # Group by category for a clear message
                secret_count = sum(1 for f in dlp_findings if f.category == DLPCategory.SECRET)
                pii_count = sum(1 for f in dlp_findings if f.category == DLPCategory.PII)
                code_count = sum(1 for f in dlp_findings if f.category == DLPCategory.SOURCE_CODE)

                parts = []
                if secret_count:
                    parts.append(f"{secret_count} secret(s)")
                if pii_count:
                    parts.append(f"{pii_count} PII instance(s)")
                if code_count:
                    parts.append("source code")

                detail = ", ".join(parts)
                first = dlp_findings[0]

                return self._block_or_coach(
                    rule_name="dlp_detection",
                    reason=(
                        f"Sensitive data detected: {detail}. "
                        f"({first.pattern_name}: {first.matched_text})"
                    ),
                    suggestion="Remove sensitive data before sending this request.",
                )

        return PolicyResult(verdict=Verdict.ALLOW)

    def _block_or_coach(
        self,
        rule_name: str,
        reason: str,
        suggestion: str = "",
    ) -> PolicyResult:
        """Return COACH if coaching is enabled, otherwise BLOCK."""
        if self._policy.coaching_enabled:
            return PolicyResult(
                verdict=Verdict.COACH,
                rule_name=rule_name,
                reason=reason,
                coaching_message=suggestion,
            )
        return PolicyResult(
            verdict=Verdict.BLOCK,
            rule_name=rule_name,
            reason=reason,
        )
