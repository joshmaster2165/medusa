"""ERR003: Verbose Error Messages.

Detects MCP server error responses that include overly detailed messages revealing internal
implementation specifics such as database table names, query structures, internal API endpoints,
configuration values, or third-party service identifiers.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.error_handling.err001_stack_trace_exposure import _err_truthy_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_VERBOSE_ERROR_KEYS = {
    "verbose_errors",
    "verbose_logging",
    "detailed_errors",
    "error_details",
    "expose_error_details",
    "show_errors",
}
_VERBOSE_ENV = {"VERBOSE_ERRORS", "DETAILED_ERRORS", "SHOW_ERROR_DETAILS"}


class VerboseErrorMessagesCheck(BaseCheck):
    """Verbose Error Messages."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _err_truthy_check(
            snapshot,
            meta,
            bad_keys=_VERBOSE_ERROR_KEYS,
            env_vars=_VERBOSE_ENV,
            fail_msg=(
                "Server '{server}' has verbose error messages enabled ({match}). "
                "Detailed errors reveal internal implementation specifics."
            ),
            pass_msg="Server '{server}' does not appear to expose verbose error details.",
        )
