"""ERR005: Information Disclosure via Errors.

Detects MCP server error responses that disclose system-level information such as operating
system details, hostname, IP addresses, user account names, installed software versions, or
runtime environment configuration.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class InformationDisclosureViaErrorsCheck(BaseCheck):
    """Information Disclosure via Errors."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        from medusa.checks.error_handling.err001_stack_trace_exposure import _err_truthy_check
        from medusa.utils.pattern_matching import ERROR_EXPOSURE_KEYS

        meta = self.metadata()
        return _err_truthy_check(
            snapshot,
            meta,
            bad_keys=ERROR_EXPOSURE_KEYS | {"expose_internals", "show_internal_errors"},
            env_vars={"EXPOSE_ERRORS", "SHOW_INTERNAL_DETAILS"},
            fail_msg=(
                "Server '{server}' has information disclosure in error responses ({match}). "
                "OS details, hostnames, or runtime info may be revealed."
            ),
            pass_msg="Server '{server}' does not appear to disclose system info in errors.",
        )
