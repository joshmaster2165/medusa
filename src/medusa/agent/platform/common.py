"""Cross-platform utilities for the Medusa Agent daemon.

Provides PID file management, signal handling, and platform detection
used by both the daemon and the CLI.
"""

from __future__ import annotations

import logging
import os
import platform
import signal
import sys
from pathlib import Path

from medusa.agent.models import PID_FILE_PATH

logger = logging.getLogger(__name__)


# ── PID File ─────────────────────────────────────────────────────────


def write_pid_file(pid: int | None = None, path: Path | None = None) -> Path:
    """Write the current process PID to the PID file.

    Returns the path to the PID file.
    """
    pid_path = path or PID_FILE_PATH
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(pid or os.getpid()))
    logger.debug("Wrote PID %d to %s", pid or os.getpid(), pid_path)
    return pid_path


def read_pid_file(path: Path | None = None) -> int | None:
    """Read the PID from the PID file, or None if not found."""
    pid_path = path or PID_FILE_PATH
    if not pid_path.exists():
        return None
    try:
        text = pid_path.read_text().strip()
        return int(text) if text else None
    except (ValueError, OSError):
        return None


def remove_pid_file(path: Path | None = None) -> None:
    """Remove the PID file if it exists."""
    pid_path = path or PID_FILE_PATH
    if pid_path.exists():
        pid_path.unlink(missing_ok=True)
        logger.debug("Removed PID file: %s", pid_path)


def is_process_alive(pid: int) -> bool:
    """Check if a process with the given PID is running.

    Works on macOS, Linux, and Windows.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)  # Signal 0 = existence check, no signal sent
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we can't signal it
        return True
    except OSError:
        return False


def is_agent_running(path: Path | None = None) -> tuple[bool, int | None]:
    """Check if the agent daemon is running.

    Returns (is_running, pid).
    """
    pid = read_pid_file(path)
    if pid is None:
        return False, None
    if is_process_alive(pid):
        return True, pid
    # Stale PID file
    remove_pid_file(path)
    return False, None


# ── Signal Handling ──────────────────────────────────────────────────


def install_signal_handlers(
    shutdown_callback: callable,
) -> None:
    """Install graceful shutdown signal handlers.

    On SIGTERM/SIGINT, calls the shutdown_callback.
    Works on macOS/Linux. On Windows, only SIGINT is supported.
    """

    def _handler(signum: int, frame: object) -> None:
        sig_name = signal.Signals(signum).name
        logger.info("Received %s, initiating graceful shutdown...", sig_name)
        shutdown_callback()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

    # SIGHUP on Unix: reload configuration
    if sys.platform != "win32":
        signal.signal(signal.SIGHUP, _handler)


# ── Platform Detection ───────────────────────────────────────────────


def get_platform() -> str:
    """Return normalized platform name: 'darwin', 'windows', or 'linux'."""
    system = platform.system().lower()
    return {
        "darwin": "darwin",
        "windows": "windows",
        "linux": "linux",
    }.get(system, "linux")


def get_daemon_manager() -> object:
    """Get the platform-specific daemon manager.

    Returns a DarwinDaemonManager, WindowsDaemonManager, or
    LinuxDaemonManager based on the current platform.

    Raises NotImplementedError for unsupported platforms.
    """
    plat = get_platform()
    if plat == "darwin":
        from medusa.agent.platform.darwin import DarwinDaemonManager

        return DarwinDaemonManager()
    elif plat == "windows":
        from medusa.agent.platform.windows import WindowsDaemonManager

        return WindowsDaemonManager()
    elif plat == "linux":
        from medusa.agent.platform.linux import LinuxDaemonManager

        return LinuxDaemonManager()
    else:
        raise NotImplementedError(
            f"Daemon management not supported on {plat}. "
            "Run the agent in foreground mode instead: medusa-agent run"
        )
