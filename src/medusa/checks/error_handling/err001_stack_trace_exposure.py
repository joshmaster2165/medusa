"""ERR001: Stack Trace Exposure.

Detects MCP server error responses that include full stack traces or exception tracebacks. Stack
traces often contain internal file paths, library versions, class names, and code logic that
help attackers understand the server internals and craft targeted exploits.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import ERROR_EXPOSURE_KEYS

_STACK_TRACE_KEYS = ERROR_EXPOSURE_KEYS | {
    "stack_trace",
    "traceback",
    "include_stacktrace",
    "show_stacktrace",
    "expose_stacktrace",
}
_STACK_TRACE_SAFE_VALUES = {"false", "0", "off", "no", "disabled"}


def _walk_config_for_keys(config: Any, keys: set[str], _depth: int = 0) -> bool:
    """Recursively walk a config dict looking for any of the given keys."""
    if _depth > 10:
        return False
    if isinstance(config, dict):
        for key in config:
            if isinstance(key, str) and key.lower() in keys:
                return True
            if _walk_config_for_keys(config[key], keys, _depth + 1):
                return True
    elif isinstance(config, list):
        for item in config:
            if _walk_config_for_keys(item, keys, _depth + 1):
                return True
    return False


def _walk_config_for_truthy_key(config: Any, keys: set[str], _depth: int = 0) -> str | None:
    """Return key=value if a dangerous key has a truthy value."""
    if _depth > 10:
        return None
    if isinstance(config, dict):
        for key, value in config.items():
            if isinstance(key, str) and key.lower() in keys:
                str_val = str(value).lower()
                if str_val not in _STACK_TRACE_SAFE_VALUES:
                    return f"{key}={value!r}"
            result = _walk_config_for_truthy_key(value, keys, _depth + 1)
            if result:
                return result
    elif isinstance(config, list):
        for item in config:
            result = _walk_config_for_truthy_key(item, keys, _depth + 1)
            if result:
                return result
    return None


def _err_truthy_check(
    snapshot: ServerSnapshot,
    meta: CheckMetadata,
    bad_keys: set[str],
    env_vars: set[str],
    fail_msg: str,
    pass_msg: str,
) -> list[Finding]:
    """FAIL if a dangerous config key is present with a truthy value or env var set."""
    match = _walk_config_for_truthy_key(snapshot.config_raw or {}, bad_keys)
    env_match = None
    if not match and snapshot.env:
        for var, val in snapshot.env.items():
            if var.upper() in env_vars:
                if str(val).lower() not in _STACK_TRACE_SAFE_VALUES:
                    env_match = f"{var}={val!r}"
                    break
    found = match or env_match
    return [
        Finding(
            check_id=meta.check_id,
            check_title=meta.title,
            status=Status.FAIL if found else Status.PASS,
            severity=meta.severity,
            server_name=snapshot.server_name,
            server_transport=snapshot.transport_type,
            resource_type="server",
            resource_name=snapshot.server_name,
            status_extended=(
                fail_msg.format(server=snapshot.server_name, match=found)
                if found
                else pass_msg.format(server=snapshot.server_name)
            ),
            evidence=str(found) if found else "no insecure error config found",
            remediation=meta.remediation,
            owasp_mcp=meta.owasp_mcp,
        )
    ]


def _err_absent_check(
    snapshot: ServerSnapshot,
    meta: CheckMetadata,
    required_keys: set[str],
    fail_msg: str,
    pass_msg: str,
) -> list[Finding]:
    """FAIL if required error-handling keys are absent from config."""
    found = _walk_config_for_keys(snapshot.config_raw or {}, required_keys)
    return [
        Finding(
            check_id=meta.check_id,
            check_title=meta.title,
            status=Status.PASS if found else Status.FAIL,
            severity=meta.severity,
            server_name=snapshot.server_name,
            server_transport=snapshot.transport_type,
            resource_type="server",
            resource_name=snapshot.server_name,
            status_extended=(
                pass_msg.format(server=snapshot.server_name)
                if found
                else fail_msg.format(server=snapshot.server_name)
            ),
            evidence=f"config_raw present: {bool(snapshot.config_raw)}",
            remediation=meta.remediation,
            owasp_mcp=meta.owasp_mcp,
        )
    ]


class StackTraceExposureCheck(BaseCheck):
    """Stack Trace Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _err_truthy_check(
            snapshot,
            meta,
            bad_keys=_STACK_TRACE_KEYS,
            env_vars={"SHOW_STACK_TRACE", "EXPOSE_ERRORS"},
            fail_msg=(
                "Server '{server}' has stack trace exposure configured ({match}). "
                "Stack traces reveal internal paths and library versions to attackers."
            ),
            pass_msg="Server '{server}' does not appear to expose stack traces.",
        )
