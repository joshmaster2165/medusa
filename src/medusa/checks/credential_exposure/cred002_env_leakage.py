"""CRED-002: Environment Variable Leakage.

Flags sensitive-looking environment variables passed to MCP server
processes, which expose credentials beyond what the server requires.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Environment variable name patterns that typically contain secrets.
# Each entry is (human_label, compiled_regex).
_SENSITIVE_ENV_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Cloud provider credentials
    ("AWS Secret Access Key", re.compile(r"^AWS_SECRET_ACCESS_KEY$", re.IGNORECASE)),
    ("AWS Session Token", re.compile(r"^AWS_SESSION_TOKEN$", re.IGNORECASE)),
    ("Azure Client Secret", re.compile(r"^AZURE_CLIENT_SECRET$", re.IGNORECASE)),
    ("GCP Service Account Key", re.compile(r"^GOOGLE_APPLICATION_CREDENTIALS$", re.IGNORECASE)),
    ("GCP Private Key", re.compile(r"^GCP_PRIVATE_KEY$", re.IGNORECASE)),
    # Database credentials
    ("Database URL", re.compile(r"^DATABASE_URL$", re.IGNORECASE)),
    (
        "Database Password",
        re.compile(
            r"^(DB|DATABASE|MYSQL|POSTGRES|PG|MONGO|REDIS)_PASSWORD$",
            re.IGNORECASE,
        ),
    ),
    ("Database Connection String", re.compile(r"^(DB|DATABASE)_CONNECTION_STRING$", re.IGNORECASE)),
    # API tokens and keys
    ("GitHub Token", re.compile(r"^(GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT)$", re.IGNORECASE)),
    ("GitLab Token", re.compile(r"^(GITLAB_TOKEN|GITLAB_PRIVATE_TOKEN)$", re.IGNORECASE)),
    ("Slack Token", re.compile(r"^(SLACK_TOKEN|SLACK_BOT_TOKEN|SLACK_WEBHOOK)$", re.IGNORECASE)),
    ("OpenAI API Key", re.compile(r"^OPENAI_API_KEY$", re.IGNORECASE)),
    ("Anthropic API Key", re.compile(r"^ANTHROPIC_API_KEY$", re.IGNORECASE)),
    ("Stripe Key", re.compile(r"^STRIPE_(SECRET_KEY|API_KEY)$", re.IGNORECASE)),
    ("SendGrid Key", re.compile(r"^SENDGRID_API_KEY$", re.IGNORECASE)),
    ("Twilio Auth Token", re.compile(r"^TWILIO_AUTH_TOKEN$", re.IGNORECASE)),
    # Generic secret/token/password patterns
    ("Generic Secret", re.compile(r"_(SECRET|SECRET_KEY|PRIVATE_KEY)$", re.IGNORECASE)),
    (
        "Generic Token",
        re.compile(
            r"_(TOKEN|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN)$",
            re.IGNORECASE,
        ),
    ),
    ("Generic Password", re.compile(r"_(PASSWORD|PASSWD|PASS)$", re.IGNORECASE)),
    ("Generic API Key", re.compile(r"_(API_KEY|APIKEY)$", re.IGNORECASE)),
    # SSH and encryption keys
    ("SSH Key", re.compile(r"^SSH_(PRIVATE_KEY|KEY)$", re.IGNORECASE)),
    ("Encryption Key", re.compile(r"^(ENCRYPTION_KEY|SIGNING_KEY|JWT_SECRET)$", re.IGNORECASE)),
    # NPM / Docker tokens
    ("NPM Token", re.compile(r"^NPM_TOKEN$", re.IGNORECASE)),
    ("Docker Password", re.compile(r"^DOCKER_(PASSWORD|TOKEN)$", re.IGNORECASE)),
]


def _redact_value(value: str, keep: int = 4) -> str:
    """Redact a value, keeping only the first few characters."""
    if len(value) <= keep:
        return "***"
    return value[:keep] + "***"


class EnvLeakageCheck(BaseCheck):
    """Check for sensitive environment variables passed to MCP servers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.env:
            # No env vars passed -- nothing to flag, but also nothing to pass.
            return []

        for env_name, env_value in sorted(snapshot.env.items()):
            for label, pattern in _SENSITIVE_ENV_PATTERNS:
                if pattern.search(env_name):
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="config",
                            resource_name=f"env.{env_name}",
                            status_extended=(
                                f"Sensitive environment variable '{env_name}' "
                                f"({label}) is passed to server "
                                f"'{snapshot.server_name}'. The server and all "
                                f"its tools have access to this credential."
                            ),
                            evidence=(f"{env_name} = {_redact_value(env_value)}"),
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )
                    break  # One match per env var is sufficient.

        # If no sensitive env vars were found, emit a PASS.
        if not findings:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="env",
                    status_extended=(
                        f"No sensitive environment variables detected in the "
                        f"{len(snapshot.env)} variable(s) passed to server "
                        f"'{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
