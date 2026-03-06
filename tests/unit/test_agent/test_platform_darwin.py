"""Tests for macOS Darwin daemon manager."""

from __future__ import annotations

from unittest.mock import patch

# Only run on macOS or allow import testing
from medusa.agent.platform.darwin import PLIST_LABEL, DarwinDaemonManager


class TestDarwinDaemonManager:
    """Tests for DarwinDaemonManager."""

    def test_init(self):
        manager = DarwinDaemonManager()
        assert manager.label == PLIST_LABEL
        assert "com.medusa.agent" in str(manager.plist_path)

    def test_generate_plist(self):
        manager = DarwinDaemonManager()
        plist = manager._generate_plist("/usr/local/bin/medusa-agent")
        assert plist["Label"] == PLIST_LABEL
        assert plist["RunAtLoad"] is True
        assert plist["KeepAlive"] is True
        assert "/usr/local/bin/medusa-agent" in plist["ProgramArguments"]
        assert plist["ProcessType"] == "Background"
        assert "ThrottleInterval" in plist

    def test_install_creates_plist(self, tmp_path):
        manager = DarwinDaemonManager()
        plist_path = tmp_path / "com.medusa.agent.plist"
        manager._plist_path = plist_path

        with (
            patch("medusa.agent.platform.darwin.LOG_DIR", tmp_path / "logs"),
            patch.object(manager, "_find_binary", return_value="/usr/local/bin/medusa-agent"),
        ):
            manager.install()

        assert plist_path.exists()

    def test_uninstall_removes_plist(self, tmp_path):
        manager = DarwinDaemonManager()
        plist_path = tmp_path / "com.medusa.agent.plist"
        plist_path.write_text("<plist></plist>")
        manager._plist_path = plist_path

        with patch("subprocess.run"):
            manager.uninstall()

        assert not plist_path.exists()
