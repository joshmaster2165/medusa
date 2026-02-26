"""Unit tests for all Credential Exposure checks (CRED-001 through CRED-003).

Each check is tested for:
- FAIL on the vulnerable_snapshot
- PASS on the secure_snapshot
- Additional edge cases specific to each check
"""

from __future__ import annotations

import pytest

from medusa.checks.credential_exposure.cred001_secrets_in_config import SecretsInConfigCheck
from medusa.checks.credential_exposure.cred002_env_leakage import EnvLeakageCheck
from medusa.checks.credential_exposure.cred003_secrets_in_definitions import (
    SecretsInDefinitionsCheck,
)
from medusa.core.check import ServerSnapshot
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

# ==========================================================================
# CRED-001: Secrets in MCP Configuration Files
# ==========================================================================


class TestCred001SecretsInConfig:
    """Tests for SecretsInConfigCheck."""

    @pytest.fixture()
    def check(self) -> SecretsInConfigCheck:
        return SecretsInConfigCheck()

    async def test_metadata_loads_correctly(self, check: SecretsInConfigCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred001"
        assert meta.category == "credential_exposure"
        assert meta.severity == Severity.CRITICAL

    async def test_fails_on_snapshot_with_real_secret(
        self, check: SecretsInConfigCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={"env": {"token": "sk-ant-abcdefghijklmnopqrstuvwxyz012345678901"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Should detect Anthropic API key pattern"

    async def test_passes_on_secure_snapshot(
        self, check: SecretsInConfigCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_detects_aws_access_key_in_config(self, check: SecretsInConfigCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"access_key": "AKIAIOSFODNN7EXAMPLE"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_detects_api_key_in_config(self, check: SecretsInConfigCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"env": {"API_KEY": "sk-ant-abc123def456ghi789jkl012mno345pqr678"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_detects_github_token_in_args(self, check: SecretsInConfigCheck) -> None:
        snapshot = make_snapshot(
            args=["--token", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_clean_config_passes(self, check: SecretsInConfigCheck) -> None:
        snapshot = make_snapshot(
            env={"NODE_ENV": "production", "PORT": "3000"},
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_empty_config_passes(self, check: SecretsInConfigCheck) -> None:
        snapshot = make_snapshot(
            env={},
            args=[],
            config_raw=None,
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_evidence_is_redacted(self, check: SecretsInConfigCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"key": "AKIAIOSFODNN7EXAMPLE"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "***" in fail_findings[0].evidence, "Secret values should be redacted"


# ==========================================================================
# CRED-002: Environment Variable Leakage
# ==========================================================================


class TestCred002EnvLeakage:
    """Tests for EnvLeakageCheck."""

    @pytest.fixture()
    def check(self) -> EnvLeakageCheck:
        return EnvLeakageCheck()

    async def test_metadata_loads_correctly(self, check: EnvLeakageCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred002"
        assert meta.category == "credential_exposure"
        assert meta.severity == Severity.HIGH

    async def test_fails_on_vulnerable_snapshot(
        self, check: EnvLeakageCheck, vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Should detect AWS_SECRET_ACCESS_KEY"

    async def test_passes_on_secure_snapshot(
        self, check: EnvLeakageCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_detects_github_token(self, check: EnvLeakageCheck) -> None:
        snapshot = make_snapshot(
            env={"GITHUB_TOKEN": "ghp_xxxxxxxxxxxx"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_detects_database_password(self, check: EnvLeakageCheck) -> None:
        snapshot = make_snapshot(
            env={"DB_PASSWORD": "supersecret"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_detects_openai_api_key(self, check: EnvLeakageCheck) -> None:
        snapshot = make_snapshot(
            env={"OPENAI_API_KEY": "sk-xxxxxxxxxxxx"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_safe_env_vars_pass(self, check: EnvLeakageCheck) -> None:
        snapshot = make_snapshot(
            env={"NODE_ENV": "production", "PORT": "3000", "HOME": "/home/user"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_empty_env_returns_nothing(self, check: EnvLeakageCheck) -> None:
        snapshot = make_snapshot(env={})
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_generic_secret_suffix(self, check: EnvLeakageCheck) -> None:
        snapshot = make_snapshot(
            env={"MY_APP_SECRET": "verysecret123"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Env vars ending in _SECRET should be flagged"


# ==========================================================================
# CRED-003: Secrets in Tool Definitions
# ==========================================================================


class TestCred003SecretsInDefinitions:
    """Tests for SecretsInDefinitionsCheck."""

    @pytest.fixture()
    def check(self) -> SecretsInDefinitionsCheck:
        return SecretsInDefinitionsCheck()

    async def test_metadata_loads_correctly(self, check: SecretsInDefinitionsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred003"
        assert meta.category == "credential_exposure"
        assert meta.severity == Severity.HIGH

    async def test_passes_on_secure_snapshot(
        self, check: SecretsInDefinitionsCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_detects_bearer_token_in_description(
        self, check: SecretsInDefinitionsCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "api_tool",
                    "description": (
                        "Call the API. Use Bearer "
                        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                        ".test.sig as auth."
                    ),
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_detects_api_key_in_default_value(
        self, check: SecretsInDefinitionsCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "keyed_tool",
                    "description": "A tool.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "api_key": {
                                "type": "string",
                                "default": "sk-ant-abc123def456ghi789jkl012mno345pqr678",
                            },
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_detects_secret_in_resource_uri(
        self, check: SecretsInDefinitionsCheck
    ) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "https://api.example.com/?token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
                    "name": "leaked_resource",
                    "description": "A resource with a token in the URI.",
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_clean_definitions_pass(self, check: SecretsInDefinitionsCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "safe_tool",
                    "description": "Returns the current time.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
            resources=[
                {
                    "uri": "config://settings",
                    "name": "settings",
                    "description": "Application settings.",
                }
            ],
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_empty_snapshot_passes(
        self, check: SecretsInDefinitionsCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS
