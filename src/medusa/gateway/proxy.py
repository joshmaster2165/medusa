"""Stdio gateway proxy for MCP traffic.

Sits between an MCP client (stdin/stdout) and the real MCP server
(child subprocess), intercepting every JSON-RPC message for policy
enforcement, DLP scanning, and audit logging.

Usage (invoked by rewritten client config):
    medusa gateway-proxy -- npx -y @modelcontextprotocol/server-everything
"""

from __future__ import annotations

import asyncio
import logging
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime

from medusa.gateway.interceptor import (
    Direction,
    MCPMessage,
    classify_message,
    make_coaching_error,
    make_error_response,
    read_message,
    write_message,
)
from medusa.gateway.policy import PolicyEngine, PolicyResult, Verdict

logger = logging.getLogger(__name__)


@dataclass
class AuditEvent:
    """A gateway audit log entry."""

    timestamp: str
    direction: str
    message_type: str
    method: str | None
    tool_name: str | None
    verdict: str
    rule_name: str
    reason: str
    server_name: str


@dataclass
class ProxyStats:
    """Running statistics for the gateway proxy."""

    messages_total: int = 0
    messages_allowed: int = 0
    messages_blocked: int = 0
    messages_coached: int = 0
    start_time: float = 0.0
    audit_log: list[AuditEvent] = field(default_factory=list)


class StdioGatewayProxy:
    """Transparent stdio proxy between MCP client and server.

    Reads JSON-RPC from its own stdin (from the MCP client),
    runs each message through the policy engine, then forwards
    to the real server's stdin (or returns a coaching error).
    Same for server → client responses.
    """

    def __init__(
        self,
        server_command: list[str],
        policy_engine: PolicyEngine,
        server_name: str = "",
        *,
        audit: bool = True,
    ) -> None:
        self._command = server_command
        self._policy = policy_engine
        self._server_name = server_name or " ".join(server_command[:2])
        self._audit = audit
        self._stats = ProxyStats()
        self._process: asyncio.subprocess.Process | None = None
        self._shutdown = asyncio.Event()

    @property
    def stats(self) -> ProxyStats:
        return self._stats

    async def run(self) -> int:
        """Run the gateway proxy until the server or client disconnects.

        Returns the server process exit code.
        """
        import time

        self._stats.start_time = time.monotonic()

        logger.info(
            "Medusa Gateway: starting proxy for '%s' → %s",
            self._server_name,
            self._command,
        )

        # Spawn the real MCP server as a child process
        try:
            self._process = await asyncio.create_subprocess_exec(
                *self._command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.error("Server command not found: %s", self._command)
            return 127
        except OSError as e:
            logger.error("Failed to start server: %s", e)
            return 1

        assert self._process.stdin is not None
        assert self._process.stdout is not None

        # Wire up stdin/stdout as asyncio streams
        client_reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(client_reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        (
            client_writer_transport,
            client_writer_protocol,
        ) = await asyncio.get_event_loop().connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout
        )
        client_writer = asyncio.StreamWriter(
            client_writer_transport, client_writer_protocol, None, asyncio.get_event_loop()
        )

        server_reader = self._process.stdout
        server_writer = self._process.stdin

        # Run bidirectional forwarding
        try:
            await asyncio.gather(
                self._forward_client_to_server(client_reader, server_writer),
                self._forward_server_to_client(server_reader, client_writer),
            )
        except asyncio.CancelledError:
            pass
        finally:
            # Cleanup
            if self._process.returncode is None:
                self._process.terminate()
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=5)
                except TimeoutError:
                    self._process.kill()

        return self._process.returncode or 0

    async def _forward_client_to_server(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Read messages from MCP client, inspect, forward to server."""
        while not self._shutdown.is_set():
            raw = await read_message(reader)
            if raw is None:
                # Client disconnected
                self._shutdown.set()
                break

            msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
            result = self._policy.evaluate(msg, server_name=self._server_name)
            self._record(msg, result)

            if result.verdict == Verdict.ALLOW:
                await write_message(writer, raw)
            elif result.verdict == Verdict.COACH:
                # Send coaching error back to client instead of forwarding
                error_resp = make_coaching_error(
                    msg_id=msg.msg_id,
                    reason=result.reason,
                    suggestion=result.coaching_message,
                )
                # Write back to the client's stdout (our stdout)
                sys.stdout.buffer.write(
                    (__import__("json").dumps(error_resp, separators=(",", ":")) + "\n").encode()
                )
                sys.stdout.buffer.flush()
            else:
                # BLOCK — silent error
                error_resp = make_error_response(
                    msg_id=msg.msg_id,
                    code=-32001,
                    message=result.reason,
                )
                sys.stdout.buffer.write(
                    (__import__("json").dumps(error_resp, separators=(",", ":")) + "\n").encode()
                )
                sys.stdout.buffer.flush()

    async def _forward_server_to_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Read messages from MCP server, inspect, forward to client."""
        while not self._shutdown.is_set():
            raw = await read_message(reader)
            if raw is None:
                # Server disconnected
                self._shutdown.set()
                break

            msg = classify_message(raw, Direction.SERVER_TO_CLIENT)
            result = self._policy.evaluate(msg, server_name=self._server_name)
            self._record(msg, result)

            if result.verdict == Verdict.ALLOW:
                await write_message(writer, raw)
            else:
                # Block server response — send error to client
                error_resp = make_error_response(
                    msg_id=msg.msg_id,
                    code=-32001,
                    message=f"Response blocked: {result.reason}",
                )
                await write_message(writer, error_resp)

    def _record(self, msg: MCPMessage, result: PolicyResult) -> None:
        """Record statistics and audit log."""
        self._stats.messages_total += 1
        if result.verdict == Verdict.ALLOW:
            self._stats.messages_allowed += 1
        elif result.verdict == Verdict.BLOCK:
            self._stats.messages_blocked += 1
        else:
            self._stats.messages_coached += 1

        if self._audit and result.verdict != Verdict.ALLOW:
            self._stats.audit_log.append(
                AuditEvent(
                    timestamp=datetime.now(UTC).isoformat(),
                    direction=msg.direction.value,
                    message_type=msg.message_type.value,
                    method=msg.method,
                    tool_name=msg.tool_name,
                    verdict=result.verdict.value,
                    rule_name=result.rule_name,
                    reason=result.reason,
                    server_name=self._server_name,
                )
            )

        if result.verdict != Verdict.ALLOW:
            logger.warning(
                "[%s] %s %s — %s: %s",
                result.verdict.upper(),
                msg.direction.value,
                msg.method or "response",
                result.rule_name,
                result.reason,
            )
