"""Unit tests for all Credential Exposure checks (CRED-001 through CRED-023).

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


# ==========================================================================
# CRED-004: GCP Service Account Key Exposure
# ==========================================================================


class TestGcpServiceAccountKeyCheck:
    """Tests for GcpServiceAccountKeyCheck."""

    @pytest.fixture()
    def check(self) -> GcpServiceAccountKeyCheck:
        return GcpServiceAccountKeyCheck()

    async def test_metadata_loads_correctly(self, check: GcpServiceAccountKeyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred004"
        assert meta.category == "credential_exposure"

    async def test_fails_on_gcp_service_account_json(
        self, check: GcpServiceAccountKeyCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={"key_json": '"type": "service_account"'},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_gcp_env_var(self, check: GcpServiceAccountKeyCheck) -> None:
        snapshot = make_snapshot(
            env={"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/key.json"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: GcpServiceAccountKeyCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
            env={"NODE_ENV": "production"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: GcpServiceAccountKeyCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-005: Azure Credentials Exposure
# ==========================================================================


class TestAzureCredentialsCheck:
    """Tests for AzureCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> AzureCredentialsCheck:
        return AzureCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: AzureCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred005"
        assert meta.category == "credential_exposure"

    async def test_fails_on_azure_client_secret_env(self, check: AzureCredentialsCheck) -> None:
        snapshot = make_snapshot(
            env={"AZURE_CLIENT_SECRET": "my-azure-client-secret-value"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_azure_shared_access_key(self, check: AzureCredentialsCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"connection": "SharedAccessKey=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=="},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: AzureCredentialsCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"PORT": "8080"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: AzureCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-006: Database Connection String
# ==========================================================================


class TestDatabaseConnectionStringCheck:
    """Tests for DatabaseConnectionStringCheck."""

    @pytest.fixture()
    def check(self) -> DatabaseConnectionStringCheck:
        return DatabaseConnectionStringCheck()

    async def test_metadata_loads_correctly(self, check: DatabaseConnectionStringCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred006"
        assert meta.category == "credential_exposure"

    async def test_fails_on_postgres_connection_string(
        self, check: DatabaseConnectionStringCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={"db_url": "postgres://user:password123@localhost:5432/mydb"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_database_url_env(self, check: DatabaseConnectionStringCheck) -> None:
        snapshot = make_snapshot(
            env={"DATABASE_URL": "mysql://admin:secret@db.example.com/app"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: DatabaseConnectionStringCheck) -> None:
        snapshot = make_snapshot(config_raw={"host": "localhost"}, env={"PORT": "5432"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: DatabaseConnectionStringCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-007: SSH Private Key Exposure
# ==========================================================================


class TestSshPrivateKeyCheck:
    """Tests for SshPrivateKeyCheck."""

    @pytest.fixture()
    def check(self) -> SshPrivateKeyCheck:
        return SshPrivateKeyCheck()

    async def test_metadata_loads_correctly(self, check: SshPrivateKeyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred007"
        assert meta.category == "credential_exposure"

    async def test_fails_on_ssh_private_key_header(self, check: SshPrivateKeyCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_ssh_key_path(self, check: SshPrivateKeyCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"identity_file": ".ssh/id_rsa"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: SshPrivateKeyCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: SshPrivateKeyCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-008: JWT Secret in Environment
# ==========================================================================


class TestJwtSecretInEnvCheck:
    """Tests for JwtSecretInEnvCheck."""

    @pytest.fixture()
    def check(self) -> JwtSecretInEnvCheck:
        return JwtSecretInEnvCheck()

    async def test_metadata_loads_correctly(self, check: JwtSecretInEnvCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred008"
        assert meta.category == "credential_exposure"

    async def test_fails_on_jwt_secret_env(self, check: JwtSecretInEnvCheck) -> None:
        snapshot = make_snapshot(
            env={"JWT_SECRET": "my-super-secret-jwt-signing-key"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_jwt_key_config(self, check: JwtSecretInEnvCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"auth": {"JWT_SIGNING_KEY": "supersecretkey"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: JwtSecretInEnvCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: JwtSecretInEnvCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-009: OAuth Client Secret
# ==========================================================================


class TestOauthClientSecretCheck:
    """Tests for OauthClientSecretCheck."""

    @pytest.fixture()
    def check(self) -> OauthClientSecretCheck:
        return OauthClientSecretCheck()

    async def test_metadata_loads_correctly(self, check: OauthClientSecretCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred009"
        assert meta.category == "credential_exposure"

    async def test_fails_on_client_secret_in_config(self, check: OauthClientSecretCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"oauth": {"client_secret": "my-oauth-secret-value"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: OauthClientSecretCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: OauthClientSecretCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-010: SMTP Credentials
# ==========================================================================


class TestSmtpCredentialsCheck:
    """Tests for SmtpCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> SmtpCredentialsCheck:
        return SmtpCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: SmtpCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred010"
        assert meta.category == "credential_exposure"

    async def test_fails_on_smtp_password_env(self, check: SmtpCredentialsCheck) -> None:
        snapshot = make_snapshot(
            env={"SMTP_PASSWORD": "my-email-password"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_smtp_uri(self, check: SmtpCredentialsCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"mail": {"url": "smtp://user:password@smtp.example.com:587"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: SmtpCredentialsCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: SmtpCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-011: Docker Registry Auth
# ==========================================================================


class TestDockerRegistryAuthCheck:
    """Tests for DockerRegistryAuthCheck."""

    @pytest.fixture()
    def check(self) -> DockerRegistryAuthCheck:
        return DockerRegistryAuthCheck()

    async def test_metadata_loads_correctly(self, check: DockerRegistryAuthCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred011"
        assert meta.category == "credential_exposure"

    async def test_fails_on_docker_auth_env(self, check: DockerRegistryAuthCheck) -> None:
        snapshot = make_snapshot(
            env={"DOCKER_AUTH_CONFIG": '{"auths":{"registry.example.com":{}}}'},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_dockerconfigjson(self, check: DockerRegistryAuthCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"secret": ".dockerconfigjson"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: DockerRegistryAuthCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "docker"}, env={"PORT": "8080"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: DockerRegistryAuthCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-012: Kubernetes Secrets
# ==========================================================================


class TestKubernetesSecretsCheck:
    """Tests for KubernetesSecretsCheck."""

    @pytest.fixture()
    def check(self) -> KubernetesSecretsCheck:
        return KubernetesSecretsCheck()

    async def test_metadata_loads_correctly(self, check: KubernetesSecretsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred012"
        assert meta.category == "credential_exposure"

    async def test_fails_on_kubeconfig_env(self, check: KubernetesSecretsCheck) -> None:
        snapshot = make_snapshot(
            env={"KUBECONFIG": "/home/user/.kube/config"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: KubernetesSecretsCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: KubernetesSecretsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-013: Terraform State Secrets
# ==========================================================================


class TestTerraformStateSecretsCheck:
    """Tests for TerraformStateSecretsCheck."""

    @pytest.fixture()
    def check(self) -> TerraformStateSecretsCheck:
        return TerraformStateSecretsCheck()

    async def test_metadata_loads_correctly(self, check: TerraformStateSecretsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred013"
        assert meta.category == "credential_exposure"

    async def test_fails_on_tf_token_env(self, check: TerraformStateSecretsCheck) -> None:
        snapshot = make_snapshot(
            env={"TF_TOKEN_app_terraform_io": "my-terraform-token"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_tfstate_reference(self, check: TerraformStateSecretsCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"state_file": "terraform.tfstate"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: TerraformStateSecretsCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: TerraformStateSecretsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-014: NPM Token Exposure
# ==========================================================================


class TestNpmTokenExposureCheck:
    """Tests for NpmTokenExposureCheck."""

    @pytest.fixture()
    def check(self) -> NpmTokenExposureCheck:
        return NpmTokenExposureCheck()

    async def test_metadata_loads_correctly(self, check: NpmTokenExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred014"
        assert meta.category == "credential_exposure"

    async def test_fails_on_npm_token_env(self, check: NpmTokenExposureCheck) -> None:
        snapshot = make_snapshot(
            env={"NPM_TOKEN": "npm_abc123def456ghi789jkl012mno345pqr678"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_npmrc_auth_token(self, check: NpmTokenExposureCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"npmrc": "//registry.npmjs.org/:_authToken=npm_secrettoken123"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: NpmTokenExposureCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: NpmTokenExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-015: PyPI Token Exposure
# ==========================================================================


class TestPypiTokenExposureCheck:
    """Tests for PypiTokenExposureCheck."""

    @pytest.fixture()
    def check(self) -> PypiTokenExposureCheck:
        return PypiTokenExposureCheck()

    async def test_metadata_loads_correctly(self, check: PypiTokenExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred015"
        assert meta.category == "credential_exposure"

    async def test_fails_on_pypi_token_env(self, check: PypiTokenExposureCheck) -> None:
        snapshot = make_snapshot(
            env={"PYPI_TOKEN": "pypi-secrettoken123"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_pypi_token_value(self, check: PypiTokenExposureCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"token": "pypi-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: PypiTokenExposureCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "python"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: PypiTokenExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-016: Encryption Key Exposure
# ==========================================================================


class TestEncryptionKeyExposureCheck:
    """Tests for EncryptionKeyExposureCheck."""

    @pytest.fixture()
    def check(self) -> EncryptionKeyExposureCheck:
        return EncryptionKeyExposureCheck()

    async def test_metadata_loads_correctly(self, check: EncryptionKeyExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred016"
        assert meta.category == "credential_exposure"

    async def test_fails_on_encryption_key_env(self, check: EncryptionKeyExposureCheck) -> None:
        snapshot = make_snapshot(
            env={"ENCRYPTION_KEY": "my-aes-256-encryption-key-value"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_master_key_config(self, check: EncryptionKeyExposureCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"crypto": {"MASTER_KEY": "master-key-value"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: EncryptionKeyExposureCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: EncryptionKeyExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-017: Webhook Secret Exposure
# ==========================================================================


class TestWebhookSecretExposureCheck:
    """Tests for WebhookSecretExposureCheck."""

    @pytest.fixture()
    def check(self) -> WebhookSecretExposureCheck:
        return WebhookSecretExposureCheck()

    async def test_metadata_loads_correctly(self, check: WebhookSecretExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred017"
        assert meta.category == "credential_exposure"

    async def test_fails_on_webhook_secret_env(self, check: WebhookSecretExposureCheck) -> None:
        snapshot = make_snapshot(
            env={"WEBHOOK_SECRET": "my-webhook-signing-secret"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_signing_secret_env(self, check: WebhookSecretExposureCheck) -> None:
        snapshot = make_snapshot(
            env={"SIGNING_SECRET": "slack-signing-secret-value"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: WebhookSecretExposureCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: WebhookSecretExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-018: LDAP Bind Credentials
# ==========================================================================


class TestLdapBindCredentialsCheck:
    """Tests for LdapBindCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> LdapBindCredentialsCheck:
        return LdapBindCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: LdapBindCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred018"
        assert meta.category == "credential_exposure"

    async def test_fails_on_ldap_password_env(self, check: LdapBindCredentialsCheck) -> None:
        snapshot = make_snapshot(
            env={"LDAP_BIND_PASSWORD": "my-ldap-bind-password"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_ldap_uri_credentials(self, check: LdapBindCredentialsCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "ldap": {"url": "ldaps://cn=admin,dc=example,dc=com:password@ldap.example.com"}
            },
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: LdapBindCredentialsCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: LdapBindCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-019: Redis Auth Exposure
# ==========================================================================


class TestRedisAuthExposureCheck:
    """Tests for RedisAuthExposureCheck."""

    @pytest.fixture()
    def check(self) -> RedisAuthExposureCheck:
        return RedisAuthExposureCheck()

    async def test_metadata_loads_correctly(self, check: RedisAuthExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred019"
        assert meta.category == "credential_exposure"

    async def test_fails_on_redis_password_env(self, check: RedisAuthExposureCheck) -> None:
        snapshot = make_snapshot(
            env={"REDIS_PASSWORD": "my-redis-auth-password"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_redis_uri_with_password(self, check: RedisAuthExposureCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"cache": {"url": "redis://:mypassword@redis.example.com:6379"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: RedisAuthExposureCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: RedisAuthExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-020: Firebase Credentials
# ==========================================================================


class TestFirebaseCredentialsCheck:
    """Tests for FirebaseCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> FirebaseCredentialsCheck:
        return FirebaseCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: FirebaseCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred020"
        assert meta.category == "credential_exposure"

    async def test_fails_on_firebase_key_env(self, check: FirebaseCredentialsCheck) -> None:
        snapshot = make_snapshot(
            env={"FIREBASE_API_KEY": "my-firebase-api-key"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_firebase_admin_sdk(self, check: FirebaseCredentialsCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"key_file": "firebase-adminsdk-abc123.json"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: FirebaseCredentialsCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: FirebaseCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-021: Twilio Credentials
# ==========================================================================


class TestTwilioCredentialsCheck:
    """Tests for TwilioCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> TwilioCredentialsCheck:
        return TwilioCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: TwilioCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred021"
        assert meta.category == "credential_exposure"

    async def test_fails_on_twilio_auth_token_env(self, check: TwilioCredentialsCheck) -> None:
        snapshot = make_snapshot(
            env={"TWILIO_AUTH_TOKEN": "my-twilio-auth-token-value"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_twilio_account_sid(self, check: TwilioCredentialsCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"twilio": {"account_sid": "AC" + "abcdef1234567890abcdef1234567890"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: TwilioCredentialsCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: TwilioCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-022: SendGrid API Key
# ==========================================================================


class TestSendgridApiKeyCheck:
    """Tests for SendgridApiKeyCheck."""

    @pytest.fixture()
    def check(self) -> SendgridApiKeyCheck:
        return SendgridApiKeyCheck()

    async def test_metadata_loads_correctly(self, check: SendgridApiKeyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred022"
        assert meta.category == "credential_exposure"

    async def test_fails_on_sendgrid_api_key_env(self, check: SendgridApiKeyCheck) -> None:
        snapshot = make_snapshot(
            env={"SENDGRID_API_KEY": "SG.my-sendgrid-api-key-value"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_sendgrid_key_value(self, check: SendgridApiKeyCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"email": {"key": "SG.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: SendgridApiKeyCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: SendgridApiKeyCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# CRED-023: Vault Token Exposure
# ==========================================================================


class TestVaultTokenExposureCheck:
    """Tests for VaultTokenExposureCheck."""

    @pytest.fixture()
    def check(self) -> VaultTokenExposureCheck:
        return VaultTokenExposureCheck()

    async def test_metadata_loads_correctly(self, check: VaultTokenExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "cred023"
        assert meta.category == "credential_exposure"

    async def test_fails_on_vault_token_env(self, check: VaultTokenExposureCheck) -> None:
        snapshot = make_snapshot(
            env={"VAULT_TOKEN": "hvs.ABCDEFGHIJKLMNOPQRSTUVWXYZ01"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_vault_token_value(self, check: VaultTokenExposureCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"vault": {"token": "hvs.ABCDEFGHIJKLMNOPQRSTUVWXYZ01"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: VaultTokenExposureCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: VaultTokenExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS
