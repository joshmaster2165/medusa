"""HARD004: Directory Listing Enabled.

Detects MCP servers with file-based resource handlers that enable directory listing, allowing
clients to enumerate all files and subdirectories within served paths. Directory listings reveal
the server file structure and expose files that may not be intended for access.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_DIR_LISTING_KEYS = {
    "directory_listing",
    "autoindex",
    "list_directory",
    "browse_directory",
    "dir_listing",
    "index_of",
}


class DirectoryListingEnabledCheck(BaseCheck):
    """Directory Listing Enabled."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=_DIR_LISTING_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' has directory listing enabled in configuration. "
                "This exposes the server file structure to enumeration."
            ),
            present_msg=("Server '{server}' does not have directory listing explicitly enabled."),
            fail_on_present=True,
        )
