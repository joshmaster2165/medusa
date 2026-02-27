"""PMT008: Prompt Argument Type Coercion.

Detects MCP prompt arguments where the argument name implies a numeric or
boolean value but the declared type is 'string', enabling type-coercion attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_NUMERIC_HINTS: frozenset[str] = frozenset(
    {
        "count",
        "num",
        "number",
        "amount",
        "size",
        "limit",
        "page",
        "id",
        "index",
        "age",
        "port",
        "timeout",
        "max",
        "min",
        "offset",
    }
)
_BOOLEAN_HINTS: frozenset[str] = frozenset(
    {
        "enable",
        "enabled",
        "disable",
        "disabled",
        "flag",
        "active",
        "is_",
        "has_",
        "allow",
        "allowed",
        "verbose",
        "debug",
        "force",
        "dry_run",
    }
)


def _name_implies_numeric(name: str) -> bool:
    lower = name.lower()
    return any(h in lower for h in _NUMERIC_HINTS)


def _name_implies_boolean(name: str) -> bool:
    lower = name.lower()
    return any(lower.startswith(h) or h in lower for h in _BOOLEAN_HINTS)


class PromptArgumentTypeCoercionCheck(BaseCheck):
    """Prompt Argument Type Coercion."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.prompts:
            return findings

        for prompt in snapshot.prompts:
            prompt_name = prompt.get("name", "<unnamed>")
            arguments = prompt.get("arguments", [])

            for arg in arguments:
                arg_name = arg.get("name", "<unnamed>")
                arg_type = arg.get("type", "string")

                if arg_type != "string":
                    continue

                reason: str | None = None
                if _name_implies_numeric(arg_name):
                    reason = f"arg '{arg_name}' name implies numeric but type is 'string'"
                elif _name_implies_boolean(arg_name):
                    reason = f"arg '{arg_name}' name implies boolean but type is 'string'"

                if reason:
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="prompt",
                            resource_name=f"{prompt_name}.{arg_name}",
                            status_extended=(
                                f"Prompt '{prompt_name}': {reason}. "
                                f"Type mismatch may enable coercion attacks."
                            ),
                            evidence=reason,
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        if not findings and snapshot.prompts:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"No argument type coercion risks detected across "
                        f"{len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
