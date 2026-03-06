"""Tests for platform common utilities."""

from __future__ import annotations

import os

from medusa.agent.platform.common import (
    get_platform,
    is_agent_running,
    is_process_alive,
    read_pid_file,
    remove_pid_file,
    write_pid_file,
)


class TestPIDFile:
    """Tests for PID file management."""

    def test_write_and_read(self, tmp_path):
        pid_path = tmp_path / "test.pid"
        write_pid_file(pid=12345, path=pid_path)
        assert read_pid_file(path=pid_path) == 12345

    def test_write_current_pid(self, tmp_path):
        pid_path = tmp_path / "test.pid"
        write_pid_file(path=pid_path)
        assert read_pid_file(path=pid_path) == os.getpid()

    def test_read_nonexistent(self, tmp_path):
        pid_path = tmp_path / "nonexistent.pid"
        assert read_pid_file(path=pid_path) is None

    def test_read_invalid_content(self, tmp_path):
        pid_path = tmp_path / "test.pid"
        pid_path.write_text("not-a-number")
        assert read_pid_file(path=pid_path) is None

    def test_read_empty(self, tmp_path):
        pid_path = tmp_path / "test.pid"
        pid_path.write_text("")
        assert read_pid_file(path=pid_path) is None

    def test_remove(self, tmp_path):
        pid_path = tmp_path / "test.pid"
        pid_path.write_text("12345")
        remove_pid_file(path=pid_path)
        assert not pid_path.exists()

    def test_remove_nonexistent(self, tmp_path):
        pid_path = tmp_path / "nonexistent.pid"
        remove_pid_file(path=pid_path)  # Should not raise


class TestProcessAlive:
    """Tests for is_process_alive."""

    def test_current_process_alive(self):
        assert is_process_alive(os.getpid()) is True

    def test_invalid_pid(self):
        assert is_process_alive(0) is False
        assert is_process_alive(-1) is False

    def test_nonexistent_pid(self):
        # Very high PID unlikely to exist
        assert is_process_alive(9999999) is False


class TestIsAgentRunning:
    """Tests for is_agent_running."""

    def test_not_running_no_pid_file(self, tmp_path):
        pid_path = tmp_path / "test.pid"
        running, pid = is_agent_running(path=pid_path)
        assert running is False
        assert pid is None

    def test_running_with_current_pid(self, tmp_path):
        pid_path = tmp_path / "test.pid"
        write_pid_file(pid=os.getpid(), path=pid_path)
        running, pid = is_agent_running(path=pid_path)
        assert running is True
        assert pid == os.getpid()

    def test_stale_pid_cleaned(self, tmp_path):
        pid_path = tmp_path / "test.pid"
        pid_path.write_text("9999999")  # Very high PID, not running
        running, pid = is_agent_running(path=pid_path)
        assert running is False
        assert pid is None
        assert not pid_path.exists()  # Stale file removed


class TestGetPlatform:
    """Tests for get_platform."""

    def test_returns_valid_platform(self):
        plat = get_platform()
        assert plat in ("darwin", "linux", "windows")
