"""Unit tests for Secrets Management checks (sm001-sm020)."""

from __future__ import annotations

import pytest

from medusa.checks.secrets_management.sm001_plaintext_secrets_in_config import (
    PlaintextSecretsInConfigCheck,
)
from medusa.checks.secrets_management.sm002_missing_secret_rotation import (
    MissingSecretRotationCheck,
)
from medusa.checks.secrets_management.sm003_secrets_in_version_control import (
    SecretsInVersionControlCheck,
)
from medusa.checks.secrets_management.sm004_missing_vault_integration import (
    MissingVaultIntegrationCheck,
)
from medusa.checks.secrets_management.sm005_hardcoded_encryption_keys import (
    HardcodedEncryptionKeysCheck,
)
from medusa.checks.secrets_management.sm006_shared_secrets_across_environments import (
    SharedSecretsAcrossEnvironmentsCheck,
)
from medusa.checks.secrets_management.sm007_missing_secret_audit import MissingSecretAuditCheck
from medusa.checks.secrets_management.sm008_insecure_secret_generation import (
    InsecureSecretGenerationCheck,
)
from medusa.checks.secrets_management.sm009_secrets_in_environment_variables import (
    SecretsInEnvironmentVariablesCheck,
)
from medusa.checks.secrets_management.sm010_missing_secret_encryption import (
    MissingSecretEncryptionCheck,
)
from medusa.checks.secrets_management.sm011_secret_sprawl import SecretSprawlCheck
from medusa.checks.secrets_management.sm012_missing_secret_revocation import (
    MissingSecretRevocationCheck,
)
from medusa.checks.secrets_management.sm013_default_secrets_in_use import DefaultSecretsInUseCheck
from medusa.checks.secrets_management.sm014_secrets_in_logs import SecretsInLogsCheck
from medusa.checks.secrets_management.sm015_missing_secret_access_control import (
    MissingSecretAccessControlCheck,
)
from medusa.checks.secrets_management.sm016_high_entropy_defaults import (
    HighEntropyDefaultsCheck,
)
from medusa.checks.secrets_management.sm017_secrets_in_tool_descriptions import (
    SecretsInToolDescriptionsCheck,
)
from medusa.checks.secrets_management.sm018_credentials_in_resources import (
    CredentialsInResourcesCheck,
)
from medusa.checks.secrets_management.sm019_weak_default_passwords import (
    WeakDefaultPasswordsCheck,
)
from medusa.checks.secrets_management.sm020_secrets_in_args import SecretsInArgsCheck
from medusa.core.models import Status
from tests.conftest import make_snapshot

# ==========================================================================
# SM-001: Plaintext Secrets in Configuration
# ==========================================================================


class TestPlaintextSecretsInConfigCheck:
    """Tests for PlaintextSecretsInConfigCheck."""

    @pytest.fixture()
    def check(self) -> PlaintextSecretsInConfigCheck:
        return PlaintextSecretsInConfigCheck()

    async def test_metadata_loads_correctly(self, check: PlaintextSecretsInConfigCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm001"
        assert meta.category == "secrets_management"

    async def test_fails_on_plaintext_password_in_config(
        self, check: PlaintextSecretsInConfigCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={"database": {"password": "mysupersecretpassword"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_api_key_in_config(self, check: PlaintextSecretsInConfigCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"auth": {"api_key": "supersecretapikey123"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: PlaintextSecretsInConfigCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node", "port": "3000"})
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_not_applicable_returns_empty(self, check: PlaintextSecretsInConfigCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-002: Missing Secret Rotation
# ==========================================================================


class TestMissingSecretRotationCheck:
    """Tests for MissingSecretRotationCheck."""

    @pytest.fixture()
    def check(self) -> MissingSecretRotationCheck:
        return MissingSecretRotationCheck()

    async def test_metadata_loads_correctly(self, check: MissingSecretRotationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm002"
        assert meta.category == "secrets_management"

    async def test_fails_when_no_rotation_config(self, check: MissingSecretRotationCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node", "env": {"NODE_ENV": "prod"}})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_when_rotation_configured(self, check: MissingSecretRotationCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"security": {"rotation": "30d", "auto_rotate": True}},
        )
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_empty(self, check: MissingSecretRotationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-003: Secrets in Version Control
# ==========================================================================


class TestSecretsInVersionControlCheck:
    """Tests for SecretsInVersionControlCheck."""

    @pytest.fixture()
    def check(self) -> SecretsInVersionControlCheck:
        return SecretsInVersionControlCheck()

    async def test_metadata_loads_correctly(self, check: SecretsInVersionControlCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm003"
        assert meta.category == "secrets_management"

    async def test_fails_on_git_path_in_config(self, check: SecretsInVersionControlCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"secrets_file": ".git/secrets.yaml"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: SecretsInVersionControlCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node", "port": "3000"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: SecretsInVersionControlCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# SM-004: Missing Vault Integration
# ==========================================================================


class TestMissingVaultIntegrationCheck:
    """Tests for MissingVaultIntegrationCheck."""

    @pytest.fixture()
    def check(self) -> MissingVaultIntegrationCheck:
        return MissingVaultIntegrationCheck()

    async def test_metadata_loads_correctly(self, check: MissingVaultIntegrationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm004"
        assert meta.category == "secrets_management"

    async def test_fails_when_no_vault_config(self, check: MissingVaultIntegrationCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node", "port": "3000"})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_when_vault_configured(self, check: MissingVaultIntegrationCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"secrets": {"vault": "https://vault.example.com"}},
        )
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_passes_when_vault_env_set(self, check: MissingVaultIntegrationCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node"},
            env={"VAULT_ADDR": "https://vault.example.com"},
        )
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_empty(self, check: MissingVaultIntegrationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-005: Hardcoded Encryption Keys
# ==========================================================================


class TestHardcodedEncryptionKeysCheck:
    """Tests for HardcodedEncryptionKeysCheck."""

    @pytest.fixture()
    def check(self) -> HardcodedEncryptionKeysCheck:
        return HardcodedEncryptionKeysCheck()

    async def test_metadata_loads_correctly(self, check: HardcodedEncryptionKeysCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm005"
        assert meta.category == "secrets_management"

    async def test_fails_on_encryption_key_env(self, check: HardcodedEncryptionKeysCheck) -> None:
        snapshot = make_snapshot(
            env={"ENCRYPTION_KEY": "hardcoded-aes-key-value"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: HardcodedEncryptionKeysCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: HardcodedEncryptionKeysCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# SM-006: Shared Secrets Across Environments
# ==========================================================================


class TestSharedSecretsAcrossEnvironmentsCheck:
    """Tests for SharedSecretsAcrossEnvironmentsCheck."""

    @pytest.fixture()
    def check(self) -> SharedSecretsAcrossEnvironmentsCheck:
        return SharedSecretsAcrossEnvironmentsCheck()

    async def test_metadata_loads_correctly(
        self, check: SharedSecretsAcrossEnvironmentsCheck
    ) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm006"
        assert meta.category == "secrets_management"

    async def test_fails_on_shared_secret_across_envs(
        self, check: SharedSecretsAcrossEnvironmentsCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={
                "dev": {"password": "sharedpassword"},
                "prod": {"password": "sharedpassword"},
            },
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(
        self, check: SharedSecretsAcrossEnvironmentsCheck
    ) -> None:
        snapshot = make_snapshot(config_raw={"command": "node", "port": "3000"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_empty(
        self, check: SharedSecretsAcrossEnvironmentsCheck
    ) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-007: Missing Secret Access Audit
# ==========================================================================


class TestMissingSecretAuditCheck:
    """Tests for MissingSecretAuditCheck."""

    @pytest.fixture()
    def check(self) -> MissingSecretAuditCheck:
        return MissingSecretAuditCheck()

    async def test_metadata_loads_correctly(self, check: MissingSecretAuditCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm007"
        assert meta.category == "secrets_management"

    async def test_fails_when_no_audit_config(self, check: MissingSecretAuditCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node", "port": "3000"})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_when_audit_configured(self, check: MissingSecretAuditCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"logging": {"audit": True, "audit_log": "/var/log/audit.log"}},
        )
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_empty(self, check: MissingSecretAuditCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-008: Insecure Secret Generation
# ==========================================================================


class TestInsecureSecretGenerationCheck:
    """Tests for InsecureSecretGenerationCheck."""

    @pytest.fixture()
    def check(self) -> InsecureSecretGenerationCheck:
        return InsecureSecretGenerationCheck()

    async def test_metadata_loads_correctly(self, check: InsecureSecretGenerationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm008"
        assert meta.category == "secrets_management"

    async def test_fails_on_random_seed_config(self, check: InsecureSecretGenerationCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"crypto": {"random_seed": "12345"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_weak_random_in_args(self, check: InsecureSecretGenerationCheck) -> None:
        snapshot = make_snapshot(
            args=["--use", "Math.random"],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: InsecureSecretGenerationCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node", "port": "3000"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: InsecureSecretGenerationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# SM-009: Secrets in Environment Variables
# ==========================================================================


class TestSecretsInEnvironmentVariablesCheck:
    """Tests for SecretsInEnvironmentVariablesCheck."""

    @pytest.fixture()
    def check(self) -> SecretsInEnvironmentVariablesCheck:
        return SecretsInEnvironmentVariablesCheck()

    async def test_metadata_loads_correctly(
        self, check: SecretsInEnvironmentVariablesCheck
    ) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm009"
        assert meta.category == "secrets_management"

    async def test_fails_on_secret_env_var(self, check: SecretsInEnvironmentVariablesCheck) -> None:
        snapshot = make_snapshot(
            env={"API_KEY": "mysecretapikey", "NODE_ENV": "production"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_env(self, check: SecretsInEnvironmentVariablesCheck) -> None:
        snapshot = make_snapshot(env={"NODE_ENV": "production", "PORT": "3000"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_empty(
        self, check: SecretsInEnvironmentVariablesCheck
    ) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-010: Missing Secret Encryption at Rest
# ==========================================================================


class TestMissingSecretEncryptionCheck:
    """Tests for MissingSecretEncryptionCheck."""

    @pytest.fixture()
    def check(self) -> MissingSecretEncryptionCheck:
        return MissingSecretEncryptionCheck()

    async def test_metadata_loads_correctly(self, check: MissingSecretEncryptionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm010"
        assert meta.category == "secrets_management"

    async def test_fails_when_no_encryption_at_rest(
        self, check: MissingSecretEncryptionCheck
    ) -> None:
        snapshot = make_snapshot(config_raw={"command": "node", "port": "3000"})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_when_encryption_configured(
        self, check: MissingSecretEncryptionCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={
                "storage": {
                    "encryption_at_rest": True,
                    "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc",
                }
            },
        )
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_empty(self, check: MissingSecretEncryptionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-011: Secret Sprawl
# ==========================================================================


class TestSecretSprawlCheck:
    """Tests for SecretSprawlCheck."""

    @pytest.fixture()
    def check(self) -> SecretSprawlCheck:
        return SecretSprawlCheck()

    async def test_metadata_loads_correctly(self, check: SecretSprawlCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm011"
        assert meta.category == "secrets_management"

    async def test_fails_on_high_secret_count(self, check: SecretSprawlCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "db_password": "pass1",
                "api_token": "tok1",
                "secret_key": "key1",
                "auth_token": "tok2",
            },
            env={"API_KEY": "key2", "AUTH_KEY": "key3", "SECRET": "s1"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_few_secrets(self, check: SecretSprawlCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node"},
            env={"NODE_ENV": "prod"},
        )
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_empty(self, check: SecretSprawlCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-012: Missing Secret Revocation
# ==========================================================================


class TestMissingSecretRevocationCheck:
    """Tests for MissingSecretRevocationCheck."""

    @pytest.fixture()
    def check(self) -> MissingSecretRevocationCheck:
        return MissingSecretRevocationCheck()

    async def test_metadata_loads_correctly(self, check: MissingSecretRevocationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm012"
        assert meta.category == "secrets_management"

    async def test_fails_when_no_revocation_config(
        self, check: MissingSecretRevocationCheck
    ) -> None:
        snapshot = make_snapshot(config_raw={"command": "node", "port": "3000"})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_when_revocation_configured(
        self, check: MissingSecretRevocationCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={"auth": {"revoke_endpoint": "/auth/revoke", "revocation": True}},
        )
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_empty(self, check: MissingSecretRevocationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-013: Default Secrets in Use
# ==========================================================================


class TestDefaultSecretsInUseCheck:
    """Tests for DefaultSecretsInUseCheck."""

    @pytest.fixture()
    def check(self) -> DefaultSecretsInUseCheck:
        return DefaultSecretsInUseCheck()

    async def test_metadata_loads_correctly(self, check: DefaultSecretsInUseCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm013"
        assert meta.category == "secrets_management"

    async def test_fails_on_default_password(self, check: DefaultSecretsInUseCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"auth": {"password": "password123"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_changeme_secret(self, check: DefaultSecretsInUseCheck) -> None:
        snapshot = make_snapshot(
            env={"SECRET_KEY": "changeme"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: DefaultSecretsInUseCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node"}, env={"NODE_ENV": "prod"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: DefaultSecretsInUseCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# SM-014: Secrets in Logs
# ==========================================================================


class TestSecretsInLogsCheck:
    """Tests for SecretsInLogsCheck."""

    @pytest.fixture()
    def check(self) -> SecretsInLogsCheck:
        return SecretsInLogsCheck()

    async def test_metadata_loads_correctly(self, check: SecretsInLogsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm014"
        assert meta.category == "secrets_management"

    async def test_fails_on_log_secrets_true(self, check: SecretsInLogsCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"logging": {"log_secrets": "true", "debug_logging": "true"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_config(self, check: SecretsInLogsCheck) -> None:
        snapshot = make_snapshot(config_raw={"command": "node", "port": "3000"})
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_pass(self, check: SecretsInLogsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert findings[0].status == Status.PASS


# ==========================================================================
# SM-015: Missing Secret Access Control
# ==========================================================================


class TestMissingSecretAccessControlCheck:
    """Tests for MissingSecretAccessControlCheck."""

    @pytest.fixture()
    def check(self) -> MissingSecretAccessControlCheck:
        return MissingSecretAccessControlCheck()

    async def test_metadata_loads_correctly(self, check: MissingSecretAccessControlCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm015"
        assert meta.category == "secrets_management"

    async def test_fails_when_no_access_control_config(
        self, check: MissingSecretAccessControlCheck
    ) -> None:
        snapshot = make_snapshot(config_raw={"command": "node", "port": "3000"})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_when_access_control_configured(
        self, check: MissingSecretAccessControlCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={"secrets": {"acl": {"read": ["app"], "write": ["admin"]}}},
        )
        findings = await check.execute(snapshot)
        assert findings[0].status == Status.PASS

    async def test_not_applicable_returns_empty(
        self, check: MissingSecretAccessControlCheck
    ) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-016: High-Entropy Default Values
# ==========================================================================


class TestHighEntropyDefaultsCheck:
    """Tests for HighEntropyDefaultsCheck."""

    @pytest.fixture()
    def check(self) -> HighEntropyDefaultsCheck:
        return HighEntropyDefaultsCheck()

    async def test_metadata_loads_correctly(self, check: HighEntropyDefaultsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm016"
        assert meta.category == "secrets_management"

    async def test_fails_on_high_entropy_default(self, check: HighEntropyDefaultsCheck) -> None:
        """Tool parameter with a high-entropy default should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "connect_api",
                    "description": "Connect to API.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "api_key": {
                                "type": "string",
                                "default": "aB3$xZ9#mK2@pL5&wQ8!rT6vY1",
                            },
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "api_key" in fail_findings[0].status_extended

    async def test_passes_on_normal_default(self, check: HighEntropyDefaultsCheck) -> None:
        """Tool parameter with a simple low-entropy default should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "greet",
                    "description": "Greet a user.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "greeting": {
                                "type": "string",
                                "default": "hello",
                            },
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_not_applicable_when_no_tools(self, check: HighEntropyDefaultsCheck) -> None:
        """No tools means no findings."""
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-017: Secrets in Tool Descriptions
# ==========================================================================


class TestSecretsInToolDescriptionsCheck:
    """Tests for SecretsInToolDescriptionsCheck."""

    @pytest.fixture()
    def check(self) -> SecretsInToolDescriptionsCheck:
        return SecretsInToolDescriptionsCheck()

    async def test_metadata_loads_correctly(self, check: SecretsInToolDescriptionsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm017"
        assert meta.category == "secrets_management"

    async def test_fails_on_secret_prefix_in_description(
        self, check: SecretsInToolDescriptionsCheck
    ) -> None:
        """Tool description containing a known secret prefix should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "auth_tool",
                    "description": "Use key sk-ant-abc123def456789012345678",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "sk-" in fail_findings[0].status_extended

    async def test_passes_on_clean_description(self, check: SecretsInToolDescriptionsCheck) -> None:
        """Tool description with no secret patterns should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "weather_tool",
                    "description": "Returns the current weather for a city.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_fails_on_credential_assignment_pattern(
        self, check: SecretsInToolDescriptionsCheck
    ) -> None:
        """Tool description containing password=<value> pattern should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "db_connect",
                    "description": "Connect to db with password=supersecretvalue123",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_not_applicable_when_no_tools(
        self, check: SecretsInToolDescriptionsCheck
    ) -> None:
        """No tools means no findings."""
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-018: Credentials in Resources
# ==========================================================================


class TestCredentialsInResourcesCheck:
    """Tests for CredentialsInResourcesCheck."""

    @pytest.fixture()
    def check(self) -> CredentialsInResourcesCheck:
        return CredentialsInResourcesCheck()

    async def test_metadata_loads_correctly(self, check: CredentialsInResourcesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm018"
        assert meta.category == "secrets_management"

    async def test_fails_on_credentials_in_uri(self, check: CredentialsInResourcesCheck) -> None:
        """Resource URI with embedded credentials should FAIL."""
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "postgres://admin:password123@db:5432",
                    "name": "Database",
                    "description": "Production database.",
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "admin" in fail_findings[0].evidence

    async def test_passes_on_clean_resource_uri(self, check: CredentialsInResourcesCheck) -> None:
        """Resource with clean URI and description should PASS."""
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "file:///app/data/users.json",
                    "name": "User Data",
                    "description": "Public user directory listing.",
                }
            ],
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_fails_on_secret_prefix_in_description(
        self, check: CredentialsInResourcesCheck
    ) -> None:
        """Resource description containing a secret prefix should FAIL."""
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "config://settings",
                    "name": "Settings",
                    "description": "Use token ghp_abcdef1234567890abcdef to authenticate.",
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_not_applicable_when_no_resources(
        self, check: CredentialsInResourcesCheck
    ) -> None:
        """No resources means no findings."""
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-019: Weak Default Passwords
# ==========================================================================


class TestWeakDefaultPasswordsCheck:
    """Tests for WeakDefaultPasswordsCheck."""

    @pytest.fixture()
    def check(self) -> WeakDefaultPasswordsCheck:
        return WeakDefaultPasswordsCheck()

    async def test_metadata_loads_correctly(self, check: WeakDefaultPasswordsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm019"
        assert meta.category == "secrets_management"

    async def test_fails_on_weak_password_default(self, check: WeakDefaultPasswordsCheck) -> None:
        """Tool parameter named 'password' with weak default should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "db_connect",
                    "description": "Connect to database.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "password": {
                                "type": "string",
                                "default": "admin123",
                            },
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "password" in fail_findings[0].status_extended

    async def test_passes_on_strong_default(self, check: WeakDefaultPasswordsCheck) -> None:
        """Tool parameter named 'password' with a strong default should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "db_connect",
                    "description": "Connect to database.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "password": {
                                "type": "string",
                                "default": "Xt9$kL3!mQ7#wR2@bN6&jF4vP8",
                            },
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_fails_on_changeme_default(self, check: WeakDefaultPasswordsCheck) -> None:
        """Tool parameter named 'auth_password' with 'changeme' default should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "setup",
                    "description": "Initial setup.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "auth_password": {
                                "type": "string",
                                "default": "changeme",
                            },
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_not_applicable_when_no_tools(self, check: WeakDefaultPasswordsCheck) -> None:
        """No tools means no findings."""
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# SM-020: Secrets in Command-Line Arguments
# ==========================================================================


class TestSecretsInArgsCheck:
    """Tests for SecretsInArgsCheck."""

    @pytest.fixture()
    def check(self) -> SecretsInArgsCheck:
        return SecretsInArgsCheck()

    async def test_metadata_loads_correctly(self, check: SecretsInArgsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sm020"
        assert meta.category == "secrets_management"

    async def test_fails_on_token_flag_in_args(self, check: SecretsInArgsCheck) -> None:
        """Args containing --token=<secret> should FAIL."""
        snapshot = make_snapshot(
            args=["server.js", "--token=sk-abc123def456"],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "--token=" in fail_findings[0].evidence

    async def test_passes_on_normal_args(self, check: SecretsInArgsCheck) -> None:
        """Normal command-line args should PASS."""
        snapshot = make_snapshot(
            args=["server.js", "--port=3000", "--host=localhost"],
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_fails_on_password_flag_in_args(self, check: SecretsInArgsCheck) -> None:
        """Args containing --password=<value> should FAIL."""
        snapshot = make_snapshot(
            args=["--password=mysecretpassword123"],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_not_applicable_for_http_transport(self, check: SecretsInArgsCheck) -> None:
        """HTTP transport should return no findings (args not applicable)."""
        snapshot = make_snapshot(
            transport_type="http",
            args=["--token=sk-abc123def456"],
        )
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_not_applicable_when_no_args(self, check: SecretsInArgsCheck) -> None:
        """No args means no findings."""
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []
