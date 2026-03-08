"""Linux daemon manager using systemd.

Manages the Medusa Agent as a systemd service that:
- Starts automatically at boot (multi-user.target)
- Auto-restarts on failure
- Logs to the systemd journal
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from medusa.agent.models import MEDUSA_DIR

logger = logging.getLogger(__name__)

UNIT_NAME = "medusa-agent.service"
UNIT_DIR = Path("/etc/systemd/system")
UNIT_PATH = UNIT_DIR / UNIT_NAME
ENV_FILE = Path("/etc/default/medusa-agent")

_UNIT_TEMPLATE = """\
[Unit]
Description=Medusa Security Agent for MCP
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={medusa_bin} agent-run
EnvironmentFile=-{env_file}
WorkingDirectory={working_dir}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=medusa-agent

[Install]
WantedBy=multi-user.target
"""


class LinuxDaemonManager:
    """Manages the Medusa Agent as a systemd service."""

    def __init__(self) -> None:
        self._unit_path = UNIT_PATH
        self._unit_name = UNIT_NAME
        self._env_file = ENV_FILE

    @property
    def unit_path(self) -> Path:
        return self._unit_path

    @property
    def unit_name(self) -> str:
        return self._unit_name

    def install(self) -> None:
        """Install the systemd unit file and enable the service."""
        medusa_bin = self._find_binary()
        unit_content = self._generate_unit(medusa_bin)

        self._unit_path.parent.mkdir(parents=True, exist_ok=True)
        self._unit_path.write_text(unit_content)
        logger.info("Installed systemd unit: %s", self._unit_path)

        # Reload systemd so it picks up the new unit file
        subprocess.run(
            ["systemctl", "daemon-reload"],
            check=False,
            capture_output=True,
        )

        # Enable auto-start at boot
        subprocess.run(
            ["systemctl", "enable", self._unit_name],
            check=False,
            capture_output=True,
        )
        logger.info("Enabled systemd service: %s", self._unit_name)

    def uninstall(self) -> None:
        """Disable and remove the systemd service."""
        self.stop()
        subprocess.run(
            ["systemctl", "disable", self._unit_name],
            check=False,
            capture_output=True,
        )
        if self._unit_path.exists():
            self._unit_path.unlink()
            logger.info("Removed systemd unit: %s", self._unit_path)
        if self._env_file.exists():
            self._env_file.unlink()
            logger.info("Removed environment file: %s", self._env_file)
        subprocess.run(
            ["systemctl", "daemon-reload"],
            check=False,
            capture_output=True,
        )

    def start(self) -> None:
        """Start the systemd service."""
        if not self._unit_path.exists():
            self.install()

        subprocess.run(
            ["systemctl", "start", self._unit_name],
            check=False,
            capture_output=True,
        )
        logger.info("Started systemd service: %s", self._unit_name)

    def stop(self) -> None:
        """Stop the systemd service."""
        subprocess.run(
            ["systemctl", "stop", self._unit_name],
            check=False,
            capture_output=True,
        )
        logger.info("Stopped systemd service: %s", self._unit_name)

    def is_running(self) -> bool:
        """Check if the systemd service is active."""
        result = subprocess.run(
            ["systemctl", "is-active", self._unit_name],
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() == "active"

    def _generate_unit(self, medusa_bin: str) -> str:
        """Generate the systemd unit file content."""
        return _UNIT_TEMPLATE.format(
            medusa_bin=medusa_bin,
            env_file=self._env_file,
            working_dir=MEDUSA_DIR,
        )

    @staticmethod
    def _find_binary() -> str:
        """Find the medusa-agent binary path."""
        for name in ["medusa-agent", "medusa"]:
            path = shutil.which(name)
            if path:
                return path
        return "medusa-agent"
