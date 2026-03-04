"""TP041: Multi-Vector Attack Signals in Tool Metadata.

Meta-check that flags tools exhibiting two or more independent attack signal
categories: (1) hidden tags or injection phrases in descriptions,
(2) dangerous parameter names, (3) suspicious defaults containing external
URLs, shell characters, or traversal patterns, (4) encoding bypass patterns.
Any single signal could be benign but 2+ independent signals indicate a
likely malicious tool.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.injection import ENCODING_BYPASS_PATTERNS
from medusa.utils.patterns.schema import SHELL_PARAM_NAMES
from medusa.utils.text_analysis import find_hidden_tags, find_injection_phrases

_CREDENTIAL_PARAMS: set[str] = {
    "password",
    "token",
    "api_key",
    "secret",
    "credential",
    "private_key",
    "passphrase",
    "auth_token",
}

_EXFIL_PARAMS: set[str] = {
    "webhook",
    "callback",
    "callback_url",
    "webhook_url",
    "notify_url",
    "upload_url",
    "forward_to",
}

_SUSPICIOUS_DEFAULT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # IP URL
    re.compile(r"\.\./"),  # Path traversal
    re.compile(r"[|;&`$]"),  # Shell metacharacters
    re.compile(
        r"https?://[a-z0-9\-]+\.(ngrok|burp|interact|oast)\.",
        re.IGNORECASE,
    ),  # Attacker infra
]


class MultiVectorAttackToolCheck(BaseCheck):
    """Multi-Vector Attack Signals in Tool Metadata."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            signals: set[str] = set()

            # Build combined description text
            parts: list[str] = [tool.get("description", "") or ""]
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            for param_def in properties.values():
                if isinstance(param_def, dict):
                    parts.append(param_def.get("description", "") or "")
            desc_text = " ".join(parts)

            # Signal 1: injection — hidden tags or injection phrases
            if desc_text.strip():
                if find_hidden_tags(desc_text) or find_injection_phrases(desc_text):
                    signals.add("injection")

            # Signal 2: dangerous_params — param names matching known bad sets
            dangerous_names = SHELL_PARAM_NAMES | _CREDENTIAL_PARAMS | _EXFIL_PARAMS
            for param_name in properties:
                if param_name.lower() in dangerous_names:
                    signals.add("dangerous_params")
                    break

            # Signal 3: dangerous_defaults — suspicious default values
            for param_def in properties.values():
                if isinstance(param_def, dict):
                    default = param_def.get("default")
                    if isinstance(default, str):
                        for pattern in _SUSPICIOUS_DEFAULT_PATTERNS:
                            if pattern.search(default):
                                signals.add("dangerous_defaults")
                                break
                    if "dangerous_defaults" in signals:
                        break

            # Signal 4: encoding — encoding bypass patterns in descriptions
            if desc_text.strip():
                for pattern in ENCODING_BYPASS_PATTERNS:
                    if pattern.search(desc_text):
                        signals.add("encoding")
                        break

            if len(signals) >= 2:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=(
                            f"Tool '{tool_name}' exhibits {len(signals)} "
                            f"independent attack signal categories: "
                            f"{', '.join(sorted(signals))}. Multiple attack "
                            f"vectors indicate likely malicious intent."
                        ),
                        evidence=(f"attack_signals={sorted(signals)}, tool={tool_name}"),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and snapshot.tools:
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
                        f"No multi-vector attack tools detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
