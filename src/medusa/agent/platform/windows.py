"""Windows daemon manager using Windows Services.

Manages the Medusa Agent as a Windows Service that:
- Starts automatically at boot
- Auto-restarts on failure
- Logs to ~/.medusa/logs/
"""

from __future__ import annotations

import logging
import shutil
import subprocess

from medusa.agent.models import LOG_DIR

logger = logging.getLogger(__name__)

SERVICE_NAME = "MedusaAgent"
SERVICE_DISPLAY_NAME = "Medusa Security Agent"
SERVICE_DESCRIPTION = (
    "Medusa endpoint security agent for MCP. "
    "Monitors MCP client traffic and enforces security policies."
)


class WindowsDaemonManager:
    """Manages the Medusa Agent as a Windows Service."""

    def __init__(self) -> None:
        self._service_name = SERVICE_NAME

    @property
    def service_name(self) -> str:
        return self._service_name

    def install(self) -> None:
        """Install the Windows Service using sc.exe."""
        LOG_DIR.mkdir(parents=True, exist_ok=True)

        medusa_bin = self._find_binary()

        # Create the service
        subprocess.run(
            [
                "sc.exe",
                "create",
                self._service_name,
                f"binPath={medusa_bin} agent-run",
                f"DisplayName={SERVICE_DISPLAY_NAME}",
                "start=auto",
            ],
            check=False,
            capture_output=True,
        )

        # Set description
        subprocess.run(
            [
                "sc.exe",
                "description",
                self._service_name,
                SERVICE_DESCRIPTION,
            ],
            check=False,
            capture_output=True,
        )

        # Configure auto-restart on failure
        subprocess.run(
            [
                "sc.exe",
                "failure",
                self._service_name,
                "reset=86400",
                "actions=restart/5000/restart/10000/restart/30000",
            ],
            check=False,
            capture_output=True,
        )

        logger.info("Installed Windows Service: %s", self._service_name)

    def uninstall(self) -> None:
        """Remove the Windows Service."""
        self.stop()
        subprocess.run(
            ["sc.exe", "delete", self._service_name],
            check=False,
            capture_output=True,
        )
        logger.info("Removed Windows Service: %s", self._service_name)

    def start(self) -> None:
        """Start the Windows Service."""
        subprocess.run(
            ["sc.exe", "start", self._service_name],
            check=False,
            capture_output=True,
        )
        logger.info("Started Windows Service: %s", self._service_name)

    def stop(self) -> None:
        """Stop the Windows Service."""
        subprocess.run(
            ["sc.exe", "stop", self._service_name],
            check=False,
            capture_output=True,
        )
        logger.info("Stopped Windows Service: %s", self._service_name)

    def is_running(self) -> bool:
        """Check if the Windows Service is running."""
        result = subprocess.run(
            ["sc.exe", "query", self._service_name],
            capture_output=True,
            text=True,
        )
        return "RUNNING" in result.stdout

    @staticmethod
    def _find_binary() -> str:
        """Find the medusa-agent binary path."""
        for name in ["medusa-agent.exe", "medusa.exe"]:
            path = shutil.which(name)
            if path:
                return path
        return "medusa-agent.exe"
