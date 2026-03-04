"""CTX011: Prompt Template Injection Vector.

Detects prompt template arguments with dangerous names (command, query,
path, url, code, sql) that become injection vectors when user-controlled
prompt arguments flow into tool invocations. Arguments without described
validation are flagged as potential indirect prompt injection entry points.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_DANGEROUS_ARG_NAMES: set[str] = {
    "command",
    "cmd",
    "query",
    "sql",
    "code",
    "script",
    "path",
    "file",
    "url",
    "shell",
    "exec",
    "expression",
    "eval",
    "template",
    "payload",
    "instruction",
    "prompt",
    "directive",
}

_VALIDATION_KEYWORDS: set[str] = {
    "validated",
    "sanitized",
    "escaped",
    "allowed values",
    "restricted",
    "must be one of",
    "enum",
    "whitelist",
    "allowlist",
    "filtered",
}


class PromptArgumentInjectionCheck(BaseCheck):
    """Prompt Template Injection Vector."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.prompts:
            return findings

        for prompt_template in snapshot.prompts:
            prompt_name: str = prompt_template.get("name", "<unnamed>")
            arguments = prompt_template.get("arguments", [])

            if not arguments:
                continue

            dangerous_args: list[str] = []
            for arg in arguments:
                if not isinstance(arg, dict):
                    continue
                arg_name = (arg.get("name", "") or "").lower()
                if arg_name not in _DANGEROUS_ARG_NAMES:
                    continue
                # Check if description mentions validation
                desc = (arg.get("description", "") or "").lower()
                has_validation = any(kw in desc for kw in _VALIDATION_KEYWORDS)
                if not has_validation:
                    dangerous_args.append(arg.get("name", arg_name))

            if dangerous_args:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="prompt",
                        resource_name=prompt_name,
                        status_extended=(
                            f"Prompt '{prompt_name}' has dangerous "
                            f"arguments without validation: "
                            f"{', '.join(dangerous_args)}. These may "
                            f"be injection vectors into tool calls."
                        ),
                        evidence=(f"dangerous_args={dangerous_args}, prompt={prompt_name}"),
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
                        f"No dangerous prompt arguments detected "
                        f"across {len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
