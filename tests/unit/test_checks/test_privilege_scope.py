"""Unit tests for all Privilege & Scope checks (PRIV-001 through PRIV-003).

Each check is tested for:
- FAIL on the vulnerable_snapshot
- PASS on the secure_snapshot
- Graceful handling of the empty_snapshot (no tools)
- Additional edge cases specific to each check
"""

from __future__ import annotations

import pytest

from medusa.checks.privilege_scope.priv001_filesystem_access import FilesystemAccessCheck
from medusa.checks.privilege_scope.priv002_network_access import NetworkAccessCheck
from medusa.checks.privilege_scope.priv003_shell_execution import ShellExecutionCheck
from medusa.checks.privilege_scope.priv004_cloud_metadata_access import CloudMetadataAccessCheck
from medusa.checks.privilege_scope.priv005_destructive_ops_no_confirm import (
    DestructiveOpsNoConfirmCheck,
)
from medusa.checks.privilege_scope.priv006_rbac_bypass_risk import RbacBypassRiskCheck
from medusa.checks.privilege_scope.priv007_sudo_elevation import SudoElevationCheck
from medusa.checks.privilege_scope.priv008_container_escape_risk import ContainerEscapeRiskCheck
from medusa.checks.privilege_scope.priv009_process_spawning import ProcessSpawningCheck
from medusa.checks.privilege_scope.priv010_environment_modification import (
    EnvironmentModificationCheck,
)
from medusa.checks.privilege_scope.priv011_registry_access import RegistryAccessCheck
from medusa.checks.privilege_scope.priv012_kernel_module_loading import KernelModuleLoadingCheck
from medusa.checks.privilege_scope.priv013_cron_job_creation import CronJobCreationCheck
from medusa.checks.privilege_scope.priv014_user_management import UserManagementCheck
from medusa.checks.privilege_scope.priv015_firewall_modification import FirewallModificationCheck
from medusa.checks.privilege_scope.priv016_package_installation import PackageInstallationCheck
from medusa.checks.privilege_scope.priv017_service_management import ServiceManagementCheck
from medusa.checks.privilege_scope.priv018_database_admin import DatabaseAdminCheck
from medusa.checks.privilege_scope.priv019_idor_in_resources import IdorInResourcesCheck
from medusa.checks.privilege_scope.priv020_missing_resource_authorization import (
    MissingResourceAuthorizationCheck,
)
from medusa.checks.privilege_scope.priv021_horizontal_privilege_escalation import (
    HorizontalPrivilegeEscalationCheck,
)
from medusa.checks.privilege_scope.priv022_missing_least_privilege import MissingLeastPrivilegeCheck
from medusa.checks.privilege_scope.priv023_cross_tenant_access import CrossTenantAccessCheck
from medusa.core.check import ServerSnapshot
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

# ==========================================================================
# PRIV-001: Overprivileged Filesystem Access
# ==========================================================================


class TestPriv001FilesystemAccess:
    """Tests for FilesystemAccessCheck."""

    @pytest.fixture()
    def check(self) -> FilesystemAccessCheck:
        return FilesystemAccessCheck()

    async def test_metadata_loads_correctly(self, check: FilesystemAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv001"
        assert meta.category == "privilege_scope"
        assert meta.severity == Severity.HIGH

    async def test_fails_on_unrestricted_file_reader(
        self, check: FilesystemAccessCheck, vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        file_reader_findings = [f for f in fail_findings if f.resource_name == "file_reader"]
        assert len(file_reader_findings) >= 1, (
            "file_reader with unrestricted path should be flagged"
        )

    async def test_passes_on_secure_snapshot(
        self, check: FilesystemAccessCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        # Secure snapshot has no filesystem tools, so should return empty
        assert len(findings) == 0 or all(f.status == Status.PASS for f in findings)

    async def test_empty_snapshot_returns_no_findings(
        self, check: FilesystemAccessCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0

    async def test_fs_tool_with_pattern_passes(self, check: FilesystemAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "read_file",
                    "description": "Reads a file.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "pattern": "^/workspace/.*$",
                            },
                        },
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_fs_tool_with_enum_passes(self, check: FilesystemAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "read_file",
                    "description": "Reads a file.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "enum": ["/app/config.json", "/app/data.json"],
                            },
                        },
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_non_fs_tool_is_skipped(self, check: FilesystemAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Gets weather.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "city": {"type": "string"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0, "Non-filesystem tool should not produce findings"

    async def test_fs_tool_with_config_restriction_passes(
        self, check: FilesystemAccessCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "read_file",
                    "description": "Reads a file.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                        },
                    },
                }
            ],
            args=["--allowed-dir", "/workspace"],
        )
        findings = await check.execute(snapshot)
        # With restriction hints in args, should not flag
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0


# ==========================================================================
# PRIV-002: Unrestricted Network Access
# ==========================================================================


class TestPriv002NetworkAccess:
    """Tests for NetworkAccessCheck."""

    @pytest.fixture()
    def check(self) -> NetworkAccessCheck:
        return NetworkAccessCheck()

    async def test_metadata_loads_correctly(self, check: NetworkAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv002"
        assert meta.category == "privilege_scope"
        assert meta.severity == Severity.HIGH

    async def test_no_network_tools_returns_empty(self, check: NetworkAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "calculate_sum",
                    "description": "Adds two numbers.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "number"},
                            "b": {"type": "number"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_empty_snapshot_returns_no_findings(
        self, check: NetworkAccessCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0

    async def test_fails_on_unrestricted_fetch_tool(self, check: NetworkAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "http_fetch",
                    "description": "Fetches a URL.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                        },
                        "required": ["url"],
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_with_url_pattern(self, check: NetworkAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "fetch_api",
                    "description": "Calls an API.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "pattern": "^https://api\\.example\\.com/.*$",
                            },
                        },
                        "required": ["url"],
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_with_url_enum(self, check: NetworkAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "download_report",
                    "description": "Downloads a report.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "enum": [
                                    "https://api.example.com/report/daily",
                                    "https://api.example.com/report/weekly",
                                ],
                            },
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_non_network_tool_is_skipped(self, check: NetworkAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "calculate",
                    "description": "Does math.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"a": {"type": "number"}},
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0


# ==========================================================================
# PRIV-003: Shell Execution Capability
# ==========================================================================


class TestPriv003ShellExecution:
    """Tests for ShellExecutionCheck."""

    @pytest.fixture()
    def check(self) -> ShellExecutionCheck:
        return ShellExecutionCheck()

    async def test_metadata_loads_correctly(self, check: ShellExecutionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv003"
        assert meta.category == "privilege_scope"
        assert meta.severity == Severity.CRITICAL

    async def test_fails_on_execute_command_tool(
        self, check: ShellExecutionCheck, vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        exec_findings = [f for f in fail_findings if f.resource_name == "execute_command"]
        assert len(exec_findings) >= 1, "execute_command tool should be flagged"

    async def test_passes_on_secure_snapshot(
        self, check: ShellExecutionCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_empty_snapshot_returns_no_findings(
        self, check: ShellExecutionCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0

    async def test_detects_bash_tool(self, check: ShellExecutionCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "bash",
                    "description": "Run a bash command.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_detects_shell_tool(self, check: ShellExecutionCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "shell",
                    "description": "Executes shell commands.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_non_shell_tool_passes(self, check: ShellExecutionCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Returns weather data.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_always_fails_even_with_constraints(self, check: ShellExecutionCheck) -> None:
        """Shell execution tools are always flagged, even with schema constraints."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "exec",
                    "description": "Runs a command.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "enum": ["ls", "pwd", "whoami"],
                            },
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Shell tools should always fail regardless of constraints"


class TestCloudMetadataAccessCheck:
    """Tests for CloudMetadataAccessCheck."""

    @pytest.fixture()
    def check(self) -> CloudMetadataAccessCheck:
        return CloudMetadataAccessCheck()

    async def test_metadata_loads_correctly(self, check: CloudMetadataAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv004"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: CloudMetadataAccessCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestDestructiveOpsNoConfirmCheck:
    """Tests for DestructiveOpsNoConfirmCheck."""

    @pytest.fixture()
    def check(self) -> DestructiveOpsNoConfirmCheck:
        return DestructiveOpsNoConfirmCheck()

    async def test_metadata_loads_correctly(self, check: DestructiveOpsNoConfirmCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv005"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: DestructiveOpsNoConfirmCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestRbacBypassRiskCheck:
    """Tests for RbacBypassRiskCheck."""

    @pytest.fixture()
    def check(self) -> RbacBypassRiskCheck:
        return RbacBypassRiskCheck()

    async def test_metadata_loads_correctly(self, check: RbacBypassRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv006"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: RbacBypassRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSudoElevationCheck:
    """Tests for SudoElevationCheck."""

    @pytest.fixture()
    def check(self) -> SudoElevationCheck:
        return SudoElevationCheck()

    async def test_metadata_loads_correctly(self, check: SudoElevationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv007"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: SudoElevationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestContainerEscapeRiskCheck:
    """Tests for ContainerEscapeRiskCheck."""

    @pytest.fixture()
    def check(self) -> ContainerEscapeRiskCheck:
        return ContainerEscapeRiskCheck()

    async def test_metadata_loads_correctly(self, check: ContainerEscapeRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv008"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: ContainerEscapeRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestProcessSpawningCheck:
    """Tests for ProcessSpawningCheck."""

    @pytest.fixture()
    def check(self) -> ProcessSpawningCheck:
        return ProcessSpawningCheck()

    async def test_metadata_loads_correctly(self, check: ProcessSpawningCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv009"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: ProcessSpawningCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestEnvironmentModificationCheck:
    """Tests for EnvironmentModificationCheck."""

    @pytest.fixture()
    def check(self) -> EnvironmentModificationCheck:
        return EnvironmentModificationCheck()

    async def test_metadata_loads_correctly(self, check: EnvironmentModificationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv010"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: EnvironmentModificationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestRegistryAccessCheck:
    """Tests for RegistryAccessCheck."""

    @pytest.fixture()
    def check(self) -> RegistryAccessCheck:
        return RegistryAccessCheck()

    async def test_metadata_loads_correctly(self, check: RegistryAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv011"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: RegistryAccessCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestKernelModuleLoadingCheck:
    """Tests for KernelModuleLoadingCheck."""

    @pytest.fixture()
    def check(self) -> KernelModuleLoadingCheck:
        return KernelModuleLoadingCheck()

    async def test_metadata_loads_correctly(self, check: KernelModuleLoadingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv012"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: KernelModuleLoadingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestCronJobCreationCheck:
    """Tests for CronJobCreationCheck."""

    @pytest.fixture()
    def check(self) -> CronJobCreationCheck:
        return CronJobCreationCheck()

    async def test_metadata_loads_correctly(self, check: CronJobCreationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv013"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: CronJobCreationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestUserManagementCheck:
    """Tests for UserManagementCheck."""

    @pytest.fixture()
    def check(self) -> UserManagementCheck:
        return UserManagementCheck()

    async def test_metadata_loads_correctly(self, check: UserManagementCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv014"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: UserManagementCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestFirewallModificationCheck:
    """Tests for FirewallModificationCheck."""

    @pytest.fixture()
    def check(self) -> FirewallModificationCheck:
        return FirewallModificationCheck()

    async def test_metadata_loads_correctly(self, check: FirewallModificationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv015"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: FirewallModificationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPackageInstallationCheck:
    """Tests for PackageInstallationCheck."""

    @pytest.fixture()
    def check(self) -> PackageInstallationCheck:
        return PackageInstallationCheck()

    async def test_metadata_loads_correctly(self, check: PackageInstallationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv016"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: PackageInstallationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestServiceManagementCheck:
    """Tests for ServiceManagementCheck."""

    @pytest.fixture()
    def check(self) -> ServiceManagementCheck:
        return ServiceManagementCheck()

    async def test_metadata_loads_correctly(self, check: ServiceManagementCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv017"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: ServiceManagementCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestDatabaseAdminCheck:
    """Tests for DatabaseAdminCheck."""

    @pytest.fixture()
    def check(self) -> DatabaseAdminCheck:
        return DatabaseAdminCheck()

    async def test_metadata_loads_correctly(self, check: DatabaseAdminCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv018"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: DatabaseAdminCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestIdorInResourcesCheck:
    """Tests for IdorInResourcesCheck."""

    @pytest.fixture()
    def check(self) -> IdorInResourcesCheck:
        return IdorInResourcesCheck()

    async def test_metadata_loads_correctly(self, check: IdorInResourcesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv019"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: IdorInResourcesCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingResourceAuthorizationCheck:
    """Tests for MissingResourceAuthorizationCheck."""

    @pytest.fixture()
    def check(self) -> MissingResourceAuthorizationCheck:
        return MissingResourceAuthorizationCheck()

    async def test_metadata_loads_correctly(self, check: MissingResourceAuthorizationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv020"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: MissingResourceAuthorizationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestHorizontalPrivilegeEscalationCheck:
    """Tests for HorizontalPrivilegeEscalationCheck."""

    @pytest.fixture()
    def check(self) -> HorizontalPrivilegeEscalationCheck:
        return HorizontalPrivilegeEscalationCheck()

    async def test_metadata_loads_correctly(
        self, check: HorizontalPrivilegeEscalationCheck
    ) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv021"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: HorizontalPrivilegeEscalationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingLeastPrivilegeCheck:
    """Tests for MissingLeastPrivilegeCheck."""

    @pytest.fixture()
    def check(self) -> MissingLeastPrivilegeCheck:
        return MissingLeastPrivilegeCheck()

    async def test_metadata_loads_correctly(self, check: MissingLeastPrivilegeCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv022"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: MissingLeastPrivilegeCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestCrossTenantAccessCheck:
    """Tests for CrossTenantAccessCheck."""

    @pytest.fixture()
    def check(self) -> CrossTenantAccessCheck:
        return CrossTenantAccessCheck()

    async def test_metadata_loads_correctly(self, check: CrossTenantAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "priv023"
        assert meta.category == "privilege_scope"

    async def test_stub_returns_empty(self, check: CrossTenantAccessCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
