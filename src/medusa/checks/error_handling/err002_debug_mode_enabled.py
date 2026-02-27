"""ERR002: Debug Mode Enabled.

Detects MCP servers running with debug or development mode flags enabled in production
environments. Debug mode typically disables security controls, enables verbose logging, exposes
diagnostic endpoints, and may auto-reload code on changes.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.error_handling.err001_stack_trace_exposure import _err_truthy_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding
from medusa.utils.pattern_matching import DEBUG_CONFIG_KEYS, DEBUG_ENV_VARS


class DebugModeEnabledCheck(BaseCheck):
    """Debug Mode Enabled."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _err_truthy_check(
            snapshot,
            meta,
            bad_keys=DEBUG_CONFIG_KEYS,
            env_vars=DEBUG_ENV_VARS,
            fail_msg=(
                "Server '{server}' has debug mode enabled ({match}). "
                "Debug mode disables security controls and exposes diagnostic endpoints."
            ),
            pass_msg="Server '{server}' does not appear to have debug mode enabled.",
        )
