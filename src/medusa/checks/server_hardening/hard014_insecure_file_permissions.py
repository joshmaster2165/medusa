"""HARD014: Insecure File Permissions.

Detects MCP server installations with overly permissive file permissions on configuration files,
credential stores, log files, and server binaries. World-readable or world-writable permissions
allow unauthorized access and modification of server components.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_FILE_PERM_KEYS = {
    "file_permissions",
    "chmod",
    "umask",
    "file_mode",
    "dir_permissions",
    "secure_file_permissions",
}


class InsecureFilePermissionsCheck(BaseCheck):
    """Insecure File Permissions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=_FILE_PERM_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' has no file permission configuration. "
                "Config files and credentials may be world-readable or world-writable."
            ),
            present_msg=("Server '{server}' has file permission configuration."),
            fail_on_present=False,
        )
