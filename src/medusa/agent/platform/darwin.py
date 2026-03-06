"""macOS daemon manager using launchd.

Manages the Medusa Agent as a launchd Launch Agent that:
- Runs at login (RunAtLoad)
- Auto-restarts on crash (KeepAlive)
- Logs to ~/.medusa/logs/
"""

from __future__ import annotations

import logging
import plistlib
import shutil
import subprocess
from pathlib import Path

from medusa.agent.models import LOG_DIR, MEDUSA_DIR

logger = logging.getLogger(__name__)

PLIST_LABEL = "com.medusa.agent"
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{PLIST_LABEL}.plist"


class DarwinDaemonManager:
    """Manages the Medusa Agent as a macOS launchd Launch Agent."""

    def __init__(self) -> None:
        self._plist_path = PLIST_PATH
        self._label = PLIST_LABEL

    @property
    def plist_path(self) -> Path:
        return self._plist_path

    @property
    def label(self) -> str:
        return self._label

    def install(self) -> None:
        """Install the launchd plist file."""
        self._plist_path.parent.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)

        medusa_bin = self._find_binary()
        plist = self._generate_plist(medusa_bin)

        with open(self._plist_path, "wb") as f:
            plistlib.dump(plist, f)

        logger.info("Installed launchd plist: %s", self._plist_path)

    def uninstall(self) -> None:
        """Remove the launchd plist and unload the service."""
        self.stop()
        if self._plist_path.exists():
            self._plist_path.unlink()
            logger.info("Removed launchd plist: %s", self._plist_path)

    def start(self) -> None:
        """Load and start the launchd service."""
        if not self._plist_path.exists():
            self.install()

        subprocess.run(
            ["launchctl", "load", "-w", str(self._plist_path)],
            check=False,
            capture_output=True,
        )
        logger.info("Started launchd service: %s", self._label)

    def stop(self) -> None:
        """Stop and unload the launchd service."""
        subprocess.run(
            ["launchctl", "unload", str(self._plist_path)],
            check=False,
            capture_output=True,
        )
        logger.info("Stopped launchd service: %s", self._label)

    def is_loaded(self) -> bool:
        """Check if the launchd service is loaded."""
        result = subprocess.run(
            ["launchctl", "list", self._label],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def _generate_plist(self, medusa_bin: str) -> dict:
        """Generate the launchd plist dictionary."""
        return {
            "Label": self._label,
            "ProgramArguments": [medusa_bin, "agent-run"],
            "RunAtLoad": True,
            "KeepAlive": True,
            "StandardOutPath": str(LOG_DIR / "agent.log"),
            "StandardErrorPath": str(LOG_DIR / "agent-error.log"),
            "WorkingDirectory": str(MEDUSA_DIR),
            "EnvironmentVariables": {
                "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
            },
            "ThrottleInterval": 10,
            "ProcessType": "Background",
        }

    @staticmethod
    def _find_binary() -> str:
        """Find the medusa-agent binary path."""
        # Check common locations
        for name in ["medusa-agent", "medusa"]:
            path = shutil.which(name)
            if path:
                return path

        # Fallback: assume it's in PATH
        return "medusa-agent"
