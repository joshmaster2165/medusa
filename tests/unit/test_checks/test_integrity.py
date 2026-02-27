"""Unit tests for Integrity checks.

Covers:
- INTG-001: Missing Version Pinning
- INTG-002: Unsigned Server Binaries
- INTG-003: Config Tampering Risk
- INTG-004: Missing Integrity Verification

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
from medusa.checks.integrity.intg005_lockfile_missing import LockfileMissingCheck
from medusa.checks.integrity.intg006_lockfile_tampered import LockfileTamperedCheck
from medusa.checks.integrity.intg007_unsigned_updates import UnsignedUpdatesCheck
from medusa.checks.integrity.intg008_missing_sbom import MissingSbomCheck
from medusa.checks.integrity.intg009_config_schema_missing import ConfigSchemaMissingCheck
from medusa.checks.integrity.intg010_tool_schema_drift import ToolSchemaDriftCheck
from medusa.checks.integrity.intg011_reproducible_build_missing import ReproducibleBuildMissingCheck
from medusa.checks.integrity.intg012_dependency_confusion_risk import DependencyConfusionRiskCheck
from medusa.checks.integrity.intg013_typosquatting_risk import TyposquattingRiskCheck
from medusa.checks.integrity.intg014_subresource_integrity_missing import (
    SubresourceIntegrityMissingCheck,
)
from medusa.checks.integrity.intg015_binary_planting_risk import BinaryPlantingRiskCheck
from medusa.checks.integrity.intg016_config_file_permissions import ConfigFilePermissionsCheck
from medusa.checks.integrity.intg017_timestamp_verification_missing import (
    TimestampVerificationMissingCheck,
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

    async def test_skips_when_no_tools(self, check: MissingIntegrityVerificationCheck) -> None:
        snapshot = make_snapshot(
            tools=[],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_fails_on_no_config(self, check: MissingIntegrityVerificationCheck) -> None:
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


class TestLockfileMissingCheck:
    """Tests for LockfileMissingCheck."""

    @pytest.fixture()
    def check(self) -> LockfileMissingCheck:
        return LockfileMissingCheck()

    async def test_metadata_loads_correctly(self, check: LockfileMissingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg005"
        assert meta.category == "integrity"

    async def test_skips_non_stdio_transport(self, check: LockfileMissingCheck) -> None:
        snapshot = make_snapshot(transport_type="http")
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_skips_non_package_manager(self, check: LockfileMissingCheck) -> None:
        snapshot = make_snapshot(
            transport_type="stdio",
            command="node",
            args=["server.js"],
        )
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_npm_without_lockfile(self, check: LockfileMissingCheck) -> None:
        snapshot = make_snapshot(
            transport_type="stdio",
            command="npm",
            args=["install", "express"],
        )
        findings = await check.execute(snapshot)
        assert len(findings) >= 1


class TestLockfileTamperedCheck:
    """Tests for LockfileTamperedCheck."""

    @pytest.fixture()
    def check(self) -> LockfileTamperedCheck:
        return LockfileTamperedCheck()

    async def test_metadata_loads_correctly(self, check: LockfileTamperedCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg006"
        assert meta.category == "integrity"

    async def test_skips_non_stdio_transport(self, check: LockfileTamperedCheck) -> None:
        snapshot = make_snapshot(transport_type="http")
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_runs_on_stdio_transport(self, check: LockfileTamperedCheck) -> None:
        snapshot = make_snapshot(
            transport_type="stdio",
            command="node",
            args=["server.js"],
        )
        findings = await check.execute(snapshot)
        assert len(findings) >= 1

    async def test_executes_without_error(self, check: LockfileTamperedCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "t", "description": "A test tool"}],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_empty_snapshot(self, check: LockfileTamperedCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestUnsignedUpdatesCheck:
    """Tests for UnsignedUpdatesCheck."""

    @pytest.fixture()
    def check(self) -> UnsignedUpdatesCheck:
        return UnsignedUpdatesCheck()

    async def test_metadata_loads_correctly(self, check: UnsignedUpdatesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg007"
        assert meta.category == "integrity"

    async def test_fails_on_missing_config_key(self, check: UnsignedUpdatesCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: UnsignedUpdatesCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "signature": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: UnsignedUpdatesCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestMissingSbomCheck:
    """Tests for MissingSbomCheck."""

    @pytest.fixture()
    def check(self) -> MissingSbomCheck:
        return MissingSbomCheck()

    async def test_metadata_loads_correctly(self, check: MissingSbomCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg008"
        assert meta.category == "integrity"

    async def test_fails_on_missing_config_key(self, check: MissingSbomCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: MissingSbomCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "sbom": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: MissingSbomCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestConfigSchemaMissingCheck:
    """Tests for ConfigSchemaMissingCheck."""

    @pytest.fixture()
    def check(self) -> ConfigSchemaMissingCheck:
        return ConfigSchemaMissingCheck()

    async def test_metadata_loads_correctly(self, check: ConfigSchemaMissingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg009"
        assert meta.category == "integrity"

    async def test_fails_on_missing_config_key(self, check: ConfigSchemaMissingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: ConfigSchemaMissingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "$schema": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: ConfigSchemaMissingCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestToolSchemaDriftCheck:
    """Tests for ToolSchemaDriftCheck."""

    @pytest.fixture()
    def check(self) -> ToolSchemaDriftCheck:
        return ToolSchemaDriftCheck()

    async def test_metadata_loads_correctly(self, check: ToolSchemaDriftCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg010"
        assert meta.category == "integrity"

    async def test_fails_on_tool_with_issues(self, check: ToolSchemaDriftCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "test_tool",
                    "description": "A test tool",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert len(findings) >= 1

    async def test_processes_tool_schemas(self, check: ToolSchemaDriftCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "t",
                    "description": "test",
                    "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
                }
            ],
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert len(findings) >= 1

    async def test_empty_tools_returns_empty(self, check: ToolSchemaDriftCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == [] or all(f.status == Status.PASS for f in findings)


class TestReproducibleBuildMissingCheck:
    """Tests for ReproducibleBuildMissingCheck."""

    @pytest.fixture()
    def check(self) -> ReproducibleBuildMissingCheck:
        return ReproducibleBuildMissingCheck()

    async def test_metadata_loads_correctly(self, check: ReproducibleBuildMissingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg011"
        assert meta.category == "integrity"

    async def test_fails_on_missing_config_key(self, check: ReproducibleBuildMissingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: ReproducibleBuildMissingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "reproducible": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: ReproducibleBuildMissingCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestDependencyConfusionRiskCheck:
    """Tests for DependencyConfusionRiskCheck."""

    @pytest.fixture()
    def check(self) -> DependencyConfusionRiskCheck:
        return DependencyConfusionRiskCheck()

    async def test_metadata_loads_correctly(self, check: DependencyConfusionRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg012"
        assert meta.category == "integrity"

    async def test_skips_non_stdio_transport(self, check: DependencyConfusionRiskCheck) -> None:
        snapshot = make_snapshot(transport_type="http")
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_runs_on_stdio_transport(self, check: DependencyConfusionRiskCheck) -> None:
        snapshot = make_snapshot(
            transport_type="stdio",
            command="node",
            args=["server.js"],
        )
        findings = await check.execute(snapshot)
        assert len(findings) >= 1

    async def test_executes_without_error(self, check: DependencyConfusionRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "t", "description": "A test tool"}],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_empty_snapshot(self, check: DependencyConfusionRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestTyposquattingRiskCheck:
    """Tests for TyposquattingRiskCheck."""

    @pytest.fixture()
    def check(self) -> TyposquattingRiskCheck:
        return TyposquattingRiskCheck()

    async def test_metadata_loads_correctly(self, check: TyposquattingRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg013"
        assert meta.category == "integrity"

    async def test_skips_non_stdio_transport(self, check: TyposquattingRiskCheck) -> None:
        snapshot = make_snapshot(transport_type="http")
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_runs_on_stdio_transport(self, check: TyposquattingRiskCheck) -> None:
        snapshot = make_snapshot(
            transport_type="stdio",
            command="node",
            args=["server.js"],
        )
        findings = await check.execute(snapshot)
        assert len(findings) >= 1

    async def test_executes_without_error(self, check: TyposquattingRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "t", "description": "A test tool"}],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_empty_snapshot(self, check: TyposquattingRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSubresourceIntegrityMissingCheck:
    """Tests for SubresourceIntegrityMissingCheck."""

    @pytest.fixture()
    def check(self) -> SubresourceIntegrityMissingCheck:
        return SubresourceIntegrityMissingCheck()

    async def test_metadata_loads_correctly(self, check: SubresourceIntegrityMissingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg014"
        assert meta.category == "integrity"

    async def test_fails_on_missing_config_key(
        self, check: SubresourceIntegrityMissingCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(
        self, check: SubresourceIntegrityMissingCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "integrity": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: SubresourceIntegrityMissingCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestBinaryPlantingRiskCheck:
    """Tests for BinaryPlantingRiskCheck."""

    @pytest.fixture()
    def check(self) -> BinaryPlantingRiskCheck:
        return BinaryPlantingRiskCheck()

    async def test_metadata_loads_correctly(self, check: BinaryPlantingRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg015"
        assert meta.category == "integrity"

    async def test_runs_on_populated_snapshot(self, check: BinaryPlantingRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "test_tool", "description": "A test tool"}],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_executes_without_error(self, check: BinaryPlantingRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "t", "description": "A test tool"}],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_empty_snapshot(self, check: BinaryPlantingRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestConfigFilePermissionsCheck:
    """Tests for ConfigFilePermissionsCheck."""

    @pytest.fixture()
    def check(self) -> ConfigFilePermissionsCheck:
        return ConfigFilePermissionsCheck()

    async def test_metadata_loads_correctly(self, check: ConfigFilePermissionsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg016"
        assert meta.category == "integrity"

    async def test_runs_on_populated_snapshot(self, check: ConfigFilePermissionsCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "test_tool", "description": "A test tool"}],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_executes_without_error(self, check: ConfigFilePermissionsCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "t", "description": "A test tool"}],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_empty_snapshot(self, check: ConfigFilePermissionsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestTimestampVerificationMissingCheck:
    """Tests for TimestampVerificationMissingCheck."""

    @pytest.fixture()
    def check(self) -> TimestampVerificationMissingCheck:
        return TimestampVerificationMissingCheck()

    async def test_metadata_loads_correctly(self, check: TimestampVerificationMissingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "intg017"
        assert meta.category == "integrity"

    async def test_fails_on_missing_config_key(
        self, check: TimestampVerificationMissingCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(
        self, check: TimestampVerificationMissingCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "timestamp": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: TimestampVerificationMissingCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
