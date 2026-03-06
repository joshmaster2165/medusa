"""Tests for gateway JSON-RPC message interceptor."""

from __future__ import annotations

import asyncio
import json

import pytest

from medusa.gateway.interceptor import (
    Direction,
    MCPMessage,
    MessageType,
    classify_message,
    make_coaching_error,
    make_error_response,
    read_message,
    write_message,
)

# ── classify_message tests ─────────────────────────────────────────────


class TestClassifyMessage:
    """Tests for classify_message function."""

    def test_initialize_request(self):
        raw = {"jsonrpc": "2.0", "method": "initialize", "id": 1, "params": {}}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        assert msg.message_type == MessageType.INITIALIZE
        assert msg.method == "initialize"
        assert msg.msg_id == 1
        assert msg.direction == Direction.CLIENT_TO_SERVER

    def test_tools_call(self):
        raw = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 5,
            "params": {
                "name": "read_file",
                "arguments": {"path": "/etc/passwd"},
            },
        }
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        assert msg.message_type == MessageType.TOOL_CALL
        assert msg.tool_name == "read_file"
        assert msg.arguments == {"path": "/etc/passwd"}
        assert msg.msg_id == 5

    def test_tools_list(self):
        raw = {"jsonrpc": "2.0", "method": "tools/list", "id": 2}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        assert msg.message_type == MessageType.TOOL_LIST
        assert msg.method == "tools/list"

    def test_resources_read(self):
        raw = {"jsonrpc": "2.0", "method": "resources/read", "id": 3}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        assert msg.message_type == MessageType.RESOURCE_READ

    def test_resources_list(self):
        raw = {"jsonrpc": "2.0", "method": "resources/list", "id": 4}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        assert msg.message_type == MessageType.RESOURCE_LIST

    def test_prompts_get(self):
        raw = {"jsonrpc": "2.0", "method": "prompts/get", "id": 6}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        assert msg.message_type == MessageType.PROMPT_GET

    def test_prompts_list(self):
        raw = {"jsonrpc": "2.0", "method": "prompts/list", "id": 7}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        assert msg.message_type == MessageType.PROMPT_LIST

    def test_notification(self):
        raw = {"jsonrpc": "2.0", "method": "notifications/cancelled"}
        msg = classify_message(raw, Direction.SERVER_TO_CLIENT)
        assert msg.message_type == MessageType.NOTIFICATION
        assert msg.msg_id is None
        assert msg.is_notification is True

    def test_response(self):
        raw = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        msg = classify_message(raw, Direction.SERVER_TO_CLIENT)
        assert msg.message_type == MessageType.RESPONSE
        assert msg.is_response is True

    def test_error_response(self):
        raw = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "Invalid request"},
        }
        msg = classify_message(raw, Direction.SERVER_TO_CLIENT)
        assert msg.message_type == MessageType.ERROR
        assert msg.error == {"code": -32600, "message": "Invalid request"}

    def test_unknown_method(self):
        raw = {"jsonrpc": "2.0", "method": "custom/method", "id": 99}
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        assert msg.message_type == MessageType.UNKNOWN

    def test_tool_call_without_args(self):
        raw = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 10,
            "params": {"name": "list_tools"},
        }
        msg = classify_message(raw, Direction.CLIENT_TO_SERVER)
        assert msg.message_type == MessageType.TOOL_CALL
        assert msg.tool_name == "list_tools"
        assert msg.arguments is None

    def test_direction_preserved(self):
        raw = {"jsonrpc": "2.0", "method": "initialize", "id": 1}
        msg_c2s = classify_message(raw, Direction.CLIENT_TO_SERVER)
        msg_s2c = classify_message(raw, Direction.SERVER_TO_CLIENT)
        assert msg_c2s.direction == Direction.CLIENT_TO_SERVER
        assert msg_s2c.direction == Direction.SERVER_TO_CLIENT


class TestMCPMessage:
    """Tests for MCPMessage properties."""

    def test_is_request(self):
        msg = MCPMessage(
            raw={"method": "tools/list", "id": 1},
            direction=Direction.CLIENT_TO_SERVER,
            message_type=MessageType.TOOL_LIST,
            method="tools/list",
            msg_id=1,
        )
        assert msg.is_request is True
        assert msg.is_response is False

    def test_is_response(self):
        msg = MCPMessage(
            raw={"result": {}, "id": 1},
            direction=Direction.SERVER_TO_CLIENT,
            message_type=MessageType.RESPONSE,
            msg_id=1,
        )
        assert msg.is_response is True
        assert msg.is_request is False

    def test_is_notification(self):
        msg = MCPMessage(
            raw={"method": "notifications/init"},
            direction=Direction.SERVER_TO_CLIENT,
            message_type=MessageType.NOTIFICATION,
            method="notifications/init",
        )
        assert msg.is_notification is True
        assert msg.is_request is True  # notifications have "method"


# ── make_error_response tests ──────────────────────────────────────────


class TestMakeErrorResponse:
    """Tests for make_error_response."""

    def test_basic_error(self):
        resp = make_error_response(msg_id=1, code=-32600, message="Bad request")
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        assert resp["error"]["code"] == -32600
        assert resp["error"]["message"] == "Bad request"
        assert "data" not in resp["error"]

    def test_error_with_data(self):
        resp = make_error_response(
            msg_id=2,
            code=-32001,
            message="Blocked",
            data={"reason": "policy"},
        )
        assert resp["error"]["data"] == {"reason": "policy"}

    def test_error_with_none_id(self):
        resp = make_error_response(msg_id=None, code=-32600, message="Error")
        assert "id" not in resp

    def test_error_with_string_id(self):
        resp = make_error_response(msg_id="abc-123", code=-32600, message="Error")
        assert resp["id"] == "abc-123"


# ── make_coaching_error tests ──────────────────────────────────────────


class TestMakeCoachingError:
    """Tests for make_coaching_error."""

    def test_coaching_error(self):
        resp = make_coaching_error(
            msg_id=5,
            reason="Tool blocked",
            suggestion="Use a different tool",
        )
        assert resp["error"]["code"] == -32001
        assert resp["error"]["message"] == "Tool blocked"
        data = resp["error"]["data"]
        assert data["blocked_by"] == "medusa-gateway"
        assert "[Medusa Gateway] Blocked: Tool blocked" in data["coaching"]
        assert "Suggestion: Use a different tool" in data["coaching"]

    def test_coaching_error_without_suggestion(self):
        resp = make_coaching_error(msg_id=1, reason="Blocked for security")
        data = resp["error"]["data"]
        assert "Suggestion" not in data["coaching"]
        assert "[Medusa Gateway] Blocked: Blocked for security" in data["coaching"]


# ── read_message / write_message tests ─────────────────────────────────


class TestReadWriteMessage:
    """Tests for async read/write functions."""

    @pytest.mark.asyncio
    async def test_read_valid_message(self):
        data = {"jsonrpc": "2.0", "method": "initialize", "id": 1}
        line = json.dumps(data) + "\n"
        reader = asyncio.StreamReader()
        reader.feed_data(line.encode("utf-8"))
        reader.feed_eof()

        result = await read_message(reader)
        assert result == data

    @pytest.mark.asyncio
    async def test_read_eof(self):
        reader = asyncio.StreamReader()
        reader.feed_eof()
        result = await read_message(reader)
        assert result is None

    @pytest.mark.asyncio
    async def test_read_invalid_json(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"not-json\n")
        reader.feed_eof()
        result = await read_message(reader)
        assert result is None

    @pytest.mark.asyncio
    async def test_read_empty_line(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\n")
        reader.feed_eof()
        result = await read_message(reader)
        assert result is None

    @pytest.mark.asyncio
    async def test_write_message(self):
        msg = {"jsonrpc": "2.0", "id": 1, "result": {}}

        # Create a mock writer
        written = bytearray()

        class FakeTransport:
            def write(self, data):
                written.extend(data)

            def get_extra_info(self, name, default=None):
                return default

            def is_closing(self):
                return False

            def close(self):
                pass

        fake_transport = FakeTransport()

        # Use StreamWriter with mock transport
        protocol = asyncio.StreamReaderProtocol(asyncio.StreamReader())
        writer = asyncio.StreamWriter(fake_transport, protocol, None, asyncio.get_event_loop())

        await write_message(writer, msg)
        output = written.decode("utf-8")
        assert output.endswith("\n")
        parsed = json.loads(output.strip())
        assert parsed == msg


class TestDirection:
    """Tests for Direction enum."""

    def test_values(self):
        assert Direction.CLIENT_TO_SERVER == "request"
        assert Direction.SERVER_TO_CLIENT == "response"


class TestMessageType:
    """Tests for MessageType enum."""

    def test_all_types_exist(self):
        expected = [
            "initialize",
            "tools/call",
            "tools/list",
            "resources/read",
            "resources/list",
            "prompts/get",
            "prompts/list",
            "notification",
            "response",
            "error",
            "unknown",
        ]
        actual = [t.value for t in MessageType]
        for e in expected:
            assert e in actual
