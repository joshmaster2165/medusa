"""Tests for Windows daemon manager."""

from __future__ import annotations

from medusa.agent.platform.windows import (
    SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
    WindowsDaemonManager,
)


class TestWindowsDaemonManager:
    """Tests for WindowsDaemonManager."""

    def test_init(self):
        manager = WindowsDaemonManager()
        assert manager.service_name == SERVICE_NAME

    def test_service_constants(self):
        assert SERVICE_NAME == "MedusaAgent"
        assert "Medusa" in SERVICE_DISPLAY_NAME
        assert "MCP" in SERVICE_DESCRIPTION
