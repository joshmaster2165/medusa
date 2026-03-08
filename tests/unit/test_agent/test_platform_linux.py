"""Tests for the Linux systemd daemon manager."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from medusa.agent.platform.linux import (
    ENV_FILE,
    UNIT_NAME,
    UNIT_PATH,
    LinuxDaemonManager,
)


class TestLinuxDaemonManager:
    """Tests for LinuxDaemonManager."""

    def setup_method(self):
        self.mgr = LinuxDaemonManager()

    def test_unit_name(self):
        assert self.mgr.unit_name == "medusa-agent.service"

    def test_unit_path(self):
        assert self.mgr.unit_path == Path("/etc/systemd/system/medusa-agent.service")

    def test_constants(self):
        assert UNIT_NAME == "medusa-agent.service"
        assert UNIT_PATH == Path("/etc/systemd/system/medusa-agent.service")
        assert ENV_FILE == Path("/etc/default/medusa-agent")


class TestGenerateUnit:
    """Tests for _generate_unit()."""

    def setup_method(self):
        self.mgr = LinuxDaemonManager()

    def test_contains_exec_start(self):
        unit = self.mgr._generate_unit("/usr/bin/medusa-agent")
        assert "ExecStart=/usr/bin/medusa-agent agent-run" in unit

    def test_contains_description(self):
        unit = self.mgr._generate_unit("medusa-agent")
        assert "Description=Medusa Security Agent for MCP" in unit

    def test_contains_restart_policy(self):
        unit = self.mgr._generate_unit("medusa-agent")
        assert "Restart=on-failure" in unit
        assert "RestartSec=10" in unit

    def test_contains_journal_output(self):
        unit = self.mgr._generate_unit("medusa-agent")
        assert "StandardOutput=journal" in unit
        assert "SyslogIdentifier=medusa-agent" in unit

    def test_contains_environment_file(self):
        unit = self.mgr._generate_unit("medusa-agent")
        assert "EnvironmentFile=-/etc/default/medusa-agent" in unit

    def test_contains_install_section(self):
        unit = self.mgr._generate_unit("medusa-agent")
        assert "WantedBy=multi-user.target" in unit

    def test_contains_network_dependency(self):
        unit = self.mgr._generate_unit("medusa-agent")
        assert "After=network-online.target" in unit


class TestFindBinary:
    """Tests for _find_binary()."""

    def test_finds_medusa_agent(self):
        with patch("shutil.which", return_value="/usr/bin/medusa-agent"):
            result = LinuxDaemonManager._find_binary()
        assert result == "/usr/bin/medusa-agent"

    def test_falls_back_to_medusa(self):
        def mock_which(name):
            if name == "medusa":
                return "/usr/local/bin/medusa"
            return None

        with patch("shutil.which", side_effect=mock_which):
            result = LinuxDaemonManager._find_binary()
        assert result == "/usr/local/bin/medusa"

    def test_fallback_string(self):
        with patch("shutil.which", return_value=None):
            result = LinuxDaemonManager._find_binary()
        assert result == "medusa-agent"


class TestInstall:
    """Tests for install()."""

    @patch("subprocess.run")
    def test_install_writes_unit_and_enables(self, mock_run, tmp_path):
        mgr = LinuxDaemonManager()
        unit_path = tmp_path / "medusa-agent.service"
        mgr._unit_path = unit_path

        with patch.object(mgr, "_find_binary", return_value="medusa-agent"):
            mgr.install()

        assert unit_path.exists()
        content = unit_path.read_text()
        assert "ExecStart=medusa-agent agent-run" in content

        # Should call daemon-reload and enable
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert ["systemctl", "daemon-reload"] in calls
        assert ["systemctl", "enable", UNIT_NAME] in calls


class TestUninstall:
    """Tests for uninstall()."""

    @patch("subprocess.run")
    def test_uninstall_removes_files(self, mock_run, tmp_path):
        mgr = LinuxDaemonManager()
        unit_path = tmp_path / "medusa-agent.service"
        env_file = tmp_path / "medusa-agent"
        unit_path.write_text("[Unit]\n")
        env_file.write_text("KEY=value\n")
        mgr._unit_path = unit_path
        mgr._env_file = env_file

        mgr.uninstall()

        assert not unit_path.exists()
        assert not env_file.exists()

        calls = [c.args[0] for c in mock_run.call_args_list]
        assert ["systemctl", "disable", UNIT_NAME] in calls


class TestStartStop:
    """Tests for start() and stop()."""

    @patch("subprocess.run")
    def test_start_calls_systemctl(self, mock_run, tmp_path):
        mgr = LinuxDaemonManager()
        # Pretend unit exists
        unit_path = tmp_path / "medusa-agent.service"
        unit_path.write_text("[Unit]\n")
        mgr._unit_path = unit_path

        mgr.start()

        calls = [c.args[0] for c in mock_run.call_args_list]
        assert ["systemctl", "start", UNIT_NAME] in calls

    @patch("subprocess.run")
    def test_start_installs_if_missing(self, mock_run, tmp_path):
        mgr = LinuxDaemonManager()
        unit_path = tmp_path / "medusa-agent.service"
        mgr._unit_path = unit_path

        with patch.object(mgr, "_find_binary", return_value="medusa-agent"):
            mgr.start()

        # Should have created the unit file first
        assert unit_path.exists()

    @patch("subprocess.run")
    def test_stop_calls_systemctl(self, mock_run):
        mgr = LinuxDaemonManager()
        mgr.stop()

        mock_run.assert_called_once_with(
            ["systemctl", "stop", UNIT_NAME],
            check=False,
            capture_output=True,
        )


class TestIsRunning:
    """Tests for is_running()."""

    @patch("subprocess.run")
    def test_is_running_active(self, mock_run):
        mock_run.return_value = MagicMock(stdout="active\n")
        mgr = LinuxDaemonManager()
        assert mgr.is_running() is True

    @patch("subprocess.run")
    def test_is_running_inactive(self, mock_run):
        mock_run.return_value = MagicMock(stdout="inactive\n")
        mgr = LinuxDaemonManager()
        assert mgr.is_running() is False

    @patch("subprocess.run")
    def test_is_running_failed(self, mock_run):
        mock_run.return_value = MagicMock(stdout="failed\n")
        mgr = LinuxDaemonManager()
        assert mgr.is_running() is False


class TestGetDaemonManagerLinux:
    """Test that get_daemon_manager returns LinuxDaemonManager on Linux."""

    @patch("medusa.agent.platform.common.get_platform", return_value="linux")
    def test_returns_linux_manager(self, _mock_plat):
        from medusa.agent.platform.common import get_daemon_manager

        mgr = get_daemon_manager()
        assert isinstance(mgr, LinuxDaemonManager)
