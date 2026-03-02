"""PMT-016: Hardcoded Secrets in Prompt Templates.

Detects API keys, tokens, and passwords hardcoded in prompt descriptions.
Prompt metadata is often visible to clients and LLMs, making embedded
secrets a direct credential exposure risk.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import is_likely_secret

# Known secret prefixes and patterns
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI API key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("Publishable key", re.compile(r"pk-[A-Za-z0-9]{20,}")),
    ("Bearer token", re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}")),
    ("Basic auth", re.compile(r"Basic\s+[A-Za-z0-9+/=]{10,}")),
    ("Token value", re.compile(r"token:\s*[A-Za-z0-9._\-]{10,}")),
    ("Password value", re.compile(r"password:\s*\S{6,}")),
    ("API key param", re.compile(r"api_key=[A-Za-z0-9._\-]{10,}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub PAT", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub OAuth", re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("Private key", re.compile(r"-----BEGIN\s+\w+\s+PRIVATE\s+KEY")),
    ("Slack token", re.compile(r"xoxb-[A-Za-z0-9\-]{20,}")),
    ("Slack token", re.compile(r"xoxp-[A-Za-z0-9\-]{20,}")),
    ("Slack token", re.compile(r"xoxa-[A-Za-z0-9\-]{20,}")),
]


class HardcodedPromptSecretsCheck(BaseCheck):
    """Hardcoded Secrets in Prompt Templates."""

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
            description = prompt.get("description", "") or ""

            if not description:
                continue

            detected: list[str] = []

            # Check against known secret patterns
            for label, pattern in _SECRET_PATTERNS:
                if pattern.search(description):
                    detected.append(label)

            # Check individual words with entropy-based heuristic
            for word in description.split():
                word_clean = word.strip(".,;:!?()[]{}\"'")
                if len(word_clean) >= 16:
                    is_secret, _confidence = is_likely_secret("prompt_value", word_clean)
                    if is_secret:
                        detected.append(f"High-entropy value: {word_clean[:8]}...")
                        break  # one entropy match is sufficient

            if detected:
                unique_detected = list(dict.fromkeys(detected))  # deduplicate
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
                            f"Prompt '{prompt_name}' description contains "
                            f"potential hardcoded secrets: "
                            f"{', '.join(unique_detected[:3])}"
                        ),
                        evidence="; ".join(unique_detected[:5]),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings:
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
                        f"No hardcoded secrets detected in prompt descriptions "
                        f"across {len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
