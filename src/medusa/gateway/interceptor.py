"""JSON-RPC message interceptor for MCP traffic.

Handles reading, parsing, and writing JSON-RPC 2.0 messages over
asyncio streams.  MCP uses newline-delimited JSON-RPC over stdio.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class Direction(StrEnum):
    """Traffic direction through the gateway."""

    CLIENT_TO_SERVER = "request"
    SERVER_TO_CLIENT = "response"


class MessageType(StrEnum):
    """Classified JSON-RPC message types relevant to MCP."""

    INITIALIZE = "initialize"
    TOOL_CALL = "tools/call"
    TOOL_LIST = "tools/list"
    RESOURCE_READ = "resources/read"
    RESOURCE_LIST = "resources/list"
    PROMPT_GET = "prompts/get"
    PROMPT_LIST = "prompts/list"
    NOTIFICATION = "notification"
    RESPONSE = "response"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class MCPMessage:
    """A parsed MCP JSON-RPC message with metadata."""

    raw: dict[str, Any]
    direction: Direction
    message_type: MessageType
    method: str | None = None
    msg_id: int | str | None = None
    tool_name: str | None = None
    arguments: dict[str, Any] | None = None
    error: dict[str, Any] | None = None

    @property
    def is_request(self) -> bool:
        return "method" in self.raw

    @property
    def is_response(self) -> bool:
        return "result" in self.raw or "error" in self.raw

    @property
    def is_notification(self) -> bool:
        return "method" in self.raw and "id" not in self.raw


def classify_message(raw: dict[str, Any], direction: Direction) -> MCPMessage:
    """Parse a raw JSON-RPC dict into a classified MCPMessage."""
    method = raw.get("method")
    msg_id = raw.get("id")
    tool_name = None
    arguments = None
    error = raw.get("error")

    # Classify message type
    if error:
        msg_type = MessageType.ERROR
    elif method is None and ("result" in raw or "error" in raw):
        msg_type = MessageType.RESPONSE
    elif method == "initialize":
        msg_type = MessageType.INITIALIZE
    elif method == "tools/call":
        msg_type = MessageType.TOOL_CALL
        params = raw.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments")
    elif method == "tools/list":
        msg_type = MessageType.TOOL_LIST
    elif method == "resources/read":
        msg_type = MessageType.RESOURCE_READ
    elif method == "resources/list":
        msg_type = MessageType.RESOURCE_LIST
    elif method == "prompts/get":
        msg_type = MessageType.PROMPT_GET
    elif method == "prompts/list":
        msg_type = MessageType.PROMPT_LIST
    elif method and msg_id is None:
        msg_type = MessageType.NOTIFICATION
    else:
        msg_type = MessageType.UNKNOWN

    return MCPMessage(
        raw=raw,
        direction=direction,
        message_type=msg_type,
        method=method,
        msg_id=msg_id,
        tool_name=tool_name,
        arguments=arguments,
        error=error,
    )


async def read_message(reader: asyncio.StreamReader) -> dict[str, Any] | None:
    """Read a single JSON-RPC message from an async stream.

    MCP stdio transport uses newline-delimited JSON.
    Returns None on EOF.
    """
    try:
        line = await reader.readline()
    except (asyncio.CancelledError, asyncio.IncompleteReadError):
        return None

    if not line:
        return None

    text = line.decode("utf-8", errors="replace").strip()
    if not text:
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.debug("Skipping non-JSON line: %s", text[:120])
        return None


async def write_message(writer: asyncio.StreamWriter, msg: dict[str, Any]) -> None:
    """Write a JSON-RPC message to an async stream."""
    data = json.dumps(msg, separators=(",", ":")) + "\n"
    writer.write(data.encode("utf-8"))
    await writer.drain()


def make_error_response(
    msg_id: int | str | None,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    resp: dict[str, Any] = {"jsonrpc": "2.0", "error": error}
    if msg_id is not None:
        resp["id"] = msg_id
    return resp


def make_coaching_error(
    msg_id: int | str | None,
    reason: str,
    suggestion: str | None = None,
) -> dict[str, Any]:
    """Build a JSON-RPC error with coaching data for the LLM agent.

    The coaching message tells the LLM *why* the action was blocked and
    suggests an alternative, so the agent can self-correct without the
    user having to intervene.
    """
    coaching = f"[Medusa Gateway] Blocked: {reason}"
    if suggestion:
        coaching += f"\nSuggestion: {suggestion}"

    return make_error_response(
        msg_id=msg_id,
        code=-32001,  # custom gateway error code
        message=reason,
        data={"coaching": coaching, "blocked_by": "medusa-gateway"},
    )
