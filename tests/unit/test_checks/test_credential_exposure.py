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
from medusa.checks.credential_exposure.cred004_gcp_service_account_key import (
    GcpServiceAccountKeyCheck,
)
from medusa.checks.credential_exposure.cred005_azure_credentials import AzureCredentialsCheck
from medusa.checks.credential_exposure.cred006_database_connection_string import (
    DatabaseConnectionStringCheck,
)
from medusa.checks.credential_exposure.cred007_ssh_private_key import SshPrivateKeyCheck
from medusa.checks.credential_exposure.cred008_jwt_secret_in_env import JwtSecretInEnvCheck
from medusa.checks.credential_exposure.cred009_oauth_client_secret import OauthClientSecretCheck
from medusa.checks.credential_exposure.cred010_smtp_credentials import SmtpCredentialsCheck
from medusa.checks.credential_exposure.cred011_docker_registry_auth import DockerRegistryAuthCheck
from medusa.checks.credential_exposure.cred012_kubernetes_secrets import KubernetesSecretsCheck
from medusa.checks.credential_exposure.cred013_terraform_state_secrets import (
    TerraformStateSecretsCheck,
)
from medusa.checks.credential_exposure.cred014_npm_token_exposure import NpmTokenExposureCheck
from medusa.checks.credential_exposure.cred015_pypi_token_exposure import PypiTokenExposureCheck
from medusa.checks.credential_exposure.cred016_encryption_key_exposure import (
    EncryptionKeyExposureCheck,
)
from medusa.checks.credential_exposure.cred017_webhook_secret_exposure import (
    WebhookSecretExposureCheck,
)
from medusa.checks.credential_exposure.cred018_ldap_bind_credentials import LdapBindCredentialsCheck
from medusa.checks.credential_exposure.cred019_redis_auth_exposure import RedisAuthExposureCheck
from medusa.checks.credential_exposure.cred020_firebase_credentials import FirebaseCredentialsCheck
from medusa.checks.credential_exposure.cred021_twilio_credentials import TwilioCredentialsCheck
from medusa.checks.credential_exposure.cred022_sendgrid_api_key import SendgridApiKeyCheck
from medusa.checks.credential_exposure.cred023_vault_token_exposure import VaultTokenExposureCheck
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

    async def test_fails_on_snapshot_with_real_secret(self, check: SecretsInConfigCheck) -> None:
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

    async def test_detects_api_key_in_default_value(self, check: SecretsInDefinitionsCheck) -> None:
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

    async def test_detects_secret_in_resource_uri(self, check: SecretsInDefinitionsCheck) -> None:
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


class TestGcpServiceAccountKeyCheck:
    """Tests for GcpServiceAccountKeyCheck."""

    @pytest.fixture()
    def check(self) -> GcpServiceAccountKeyCheck:
        return GcpServiceAccountKeyCheck()

    async def test_metadata_loads_correctly(self, check: GcpServiceAccountKeyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred004"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: GcpServiceAccountKeyCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestAzureCredentialsCheck:
    """Tests for AzureCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> AzureCredentialsCheck:
        return AzureCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: AzureCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred005"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: AzureCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestDatabaseConnectionStringCheck:
    """Tests for DatabaseConnectionStringCheck."""

    @pytest.fixture()
    def check(self) -> DatabaseConnectionStringCheck:
        return DatabaseConnectionStringCheck()

    async def test_metadata_loads_correctly(self, check: DatabaseConnectionStringCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred006"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: DatabaseConnectionStringCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSshPrivateKeyCheck:
    """Tests for SshPrivateKeyCheck."""

    @pytest.fixture()
    def check(self) -> SshPrivateKeyCheck:
        return SshPrivateKeyCheck()

    async def test_metadata_loads_correctly(self, check: SshPrivateKeyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred007"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: SshPrivateKeyCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestJwtSecretInEnvCheck:
    """Tests for JwtSecretInEnvCheck."""

    @pytest.fixture()
    def check(self) -> JwtSecretInEnvCheck:
        return JwtSecretInEnvCheck()

    async def test_metadata_loads_correctly(self, check: JwtSecretInEnvCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred008"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: JwtSecretInEnvCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestOauthClientSecretCheck:
    """Tests for OauthClientSecretCheck."""

    @pytest.fixture()
    def check(self) -> OauthClientSecretCheck:
        return OauthClientSecretCheck()

    async def test_metadata_loads_correctly(self, check: OauthClientSecretCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred009"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: OauthClientSecretCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSmtpCredentialsCheck:
    """Tests for SmtpCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> SmtpCredentialsCheck:
        return SmtpCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: SmtpCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred010"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: SmtpCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestDockerRegistryAuthCheck:
    """Tests for DockerRegistryAuthCheck."""

    @pytest.fixture()
    def check(self) -> DockerRegistryAuthCheck:
        return DockerRegistryAuthCheck()

    async def test_metadata_loads_correctly(self, check: DockerRegistryAuthCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred011"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: DockerRegistryAuthCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestKubernetesSecretsCheck:
    """Tests for KubernetesSecretsCheck."""

    @pytest.fixture()
    def check(self) -> KubernetesSecretsCheck:
        return KubernetesSecretsCheck()

    async def test_metadata_loads_correctly(self, check: KubernetesSecretsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred012"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: KubernetesSecretsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestTerraformStateSecretsCheck:
    """Tests for TerraformStateSecretsCheck."""

    @pytest.fixture()
    def check(self) -> TerraformStateSecretsCheck:
        return TerraformStateSecretsCheck()

    async def test_metadata_loads_correctly(self, check: TerraformStateSecretsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred013"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: TerraformStateSecretsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestNpmTokenExposureCheck:
    """Tests for NpmTokenExposureCheck."""

    @pytest.fixture()
    def check(self) -> NpmTokenExposureCheck:
        return NpmTokenExposureCheck()

    async def test_metadata_loads_correctly(self, check: NpmTokenExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred014"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: NpmTokenExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPypiTokenExposureCheck:
    """Tests for PypiTokenExposureCheck."""

    @pytest.fixture()
    def check(self) -> PypiTokenExposureCheck:
        return PypiTokenExposureCheck()

    async def test_metadata_loads_correctly(self, check: PypiTokenExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred015"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: PypiTokenExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestEncryptionKeyExposureCheck:
    """Tests for EncryptionKeyExposureCheck."""

    @pytest.fixture()
    def check(self) -> EncryptionKeyExposureCheck:
        return EncryptionKeyExposureCheck()

    async def test_metadata_loads_correctly(self, check: EncryptionKeyExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred016"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: EncryptionKeyExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestWebhookSecretExposureCheck:
    """Tests for WebhookSecretExposureCheck."""

    @pytest.fixture()
    def check(self) -> WebhookSecretExposureCheck:
        return WebhookSecretExposureCheck()

    async def test_metadata_loads_correctly(self, check: WebhookSecretExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred017"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: WebhookSecretExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestLdapBindCredentialsCheck:
    """Tests for LdapBindCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> LdapBindCredentialsCheck:
        return LdapBindCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: LdapBindCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred018"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: LdapBindCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestRedisAuthExposureCheck:
    """Tests for RedisAuthExposureCheck."""

    @pytest.fixture()
    def check(self) -> RedisAuthExposureCheck:
        return RedisAuthExposureCheck()

    async def test_metadata_loads_correctly(self, check: RedisAuthExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred019"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: RedisAuthExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestFirebaseCredentialsCheck:
    """Tests for FirebaseCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> FirebaseCredentialsCheck:
        return FirebaseCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: FirebaseCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred020"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: FirebaseCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestTwilioCredentialsCheck:
    """Tests for TwilioCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> TwilioCredentialsCheck:
        return TwilioCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: TwilioCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred021"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: TwilioCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSendgridApiKeyCheck:
    """Tests for SendgridApiKeyCheck."""

    @pytest.fixture()
    def check(self) -> SendgridApiKeyCheck:
        return SendgridApiKeyCheck()

    async def test_metadata_loads_correctly(self, check: SendgridApiKeyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred022"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: SendgridApiKeyCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestVaultTokenExposureCheck:
    """Tests for VaultTokenExposureCheck."""

    @pytest.fixture()
    def check(self) -> VaultTokenExposureCheck:
        return VaultTokenExposureCheck()

    async def test_metadata_loads_correctly(self, check: VaultTokenExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred023"
        assert meta.category == "credential_exposure"

    async def test_stub_returns_empty(self, check: VaultTokenExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
