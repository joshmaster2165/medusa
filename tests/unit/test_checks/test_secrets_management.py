"""Unit tests for Secrets Management checks (sm001-sm015)."""

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
