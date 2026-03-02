"""Unit tests for Server Hardening checks (auto-generated stubs)."""

from __future__ import annotations

import pytest

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    UnnecessaryServicesEnabledCheck,
)
from medusa.checks.server_hardening.hard002_default_configuration import DefaultConfigurationCheck
from medusa.checks.server_hardening.hard003_missing_security_headers import (
    MissingSecurityHeadersCheck,
)
from medusa.checks.server_hardening.hard004_directory_listing_enabled import (
    DirectoryListingEnabledCheck,
)
from medusa.checks.server_hardening.hard005_admin_interface_exposed import (
    AdminInterfaceExposedCheck,
)
from medusa.checks.server_hardening.hard006_debug_endpoints_enabled import (
    DebugEndpointsEnabledCheck,
)
from medusa.checks.server_hardening.hard007_missing_input_sanitization import (
    MissingInputSanitizationCheck,
)
from medusa.checks.server_hardening.hard008_insecure_default_credentials import (
    InsecureDefaultCredentialsCheck,
)
from medusa.checks.server_hardening.hard009_missing_security_updates import (
    MissingSecurityUpdatesCheck,
)
from medusa.checks.server_hardening.hard010_exposed_version_information import (
    ExposedVersionInformationCheck,
)
from medusa.checks.server_hardening.hard011_missing_resource_limits import (
    MissingResourceLimitsCheck,
)
from medusa.checks.server_hardening.hard012_unnecessary_http_methods import (
    UnnecessaryHttpMethodsCheck,
)
from medusa.checks.server_hardening.hard013_missing_request_validation import (
    MissingRequestValidationCheck,
)
from medusa.checks.server_hardening.hard014_insecure_file_permissions import (
    InsecureFilePermissionsCheck,
)
from medusa.checks.server_hardening.hard015_missing_network_segmentation import (
    MissingNetworkSegmentationCheck,
)
from medusa.checks.server_hardening.hard016_debug_mode import DebugModeCheck
from medusa.checks.server_hardening.hard017_permissive_capabilities import (
    PermissiveCapabilitiesCheck,
)
from medusa.checks.server_hardening.hard018_unrestricted_execution_scope import (
    UnrestrictedExecutionScopeCheck,
)
from medusa.core.models import Status
from tests.conftest import make_snapshot


class TestUnnecessaryServicesEnabledCheck:
    """Tests for UnnecessaryServicesEnabledCheck."""

    @pytest.fixture()
    def check(self) -> UnnecessaryServicesEnabledCheck:
        return UnnecessaryServicesEnabledCheck()

    async def test_metadata_loads_correctly(self, check: UnnecessaryServicesEnabledCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard001"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: UnnecessaryServicesEnabledCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestDefaultConfigurationCheck:
    """Tests for DefaultConfigurationCheck."""

    @pytest.fixture()
    def check(self) -> DefaultConfigurationCheck:
        return DefaultConfigurationCheck()

    async def test_metadata_loads_correctly(self, check: DefaultConfigurationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard002"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: DefaultConfigurationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingSecurityHeadersCheck:
    """Tests for MissingSecurityHeadersCheck."""

    @pytest.fixture()
    def check(self) -> MissingSecurityHeadersCheck:
        return MissingSecurityHeadersCheck()

    async def test_metadata_loads_correctly(self, check: MissingSecurityHeadersCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard003"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: MissingSecurityHeadersCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestDirectoryListingEnabledCheck:
    """Tests for DirectoryListingEnabledCheck."""

    @pytest.fixture()
    def check(self) -> DirectoryListingEnabledCheck:
        return DirectoryListingEnabledCheck()

    async def test_metadata_loads_correctly(self, check: DirectoryListingEnabledCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard004"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: DirectoryListingEnabledCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestAdminInterfaceExposedCheck:
    """Tests for AdminInterfaceExposedCheck."""

    @pytest.fixture()
    def check(self) -> AdminInterfaceExposedCheck:
        return AdminInterfaceExposedCheck()

    async def test_metadata_loads_correctly(self, check: AdminInterfaceExposedCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard005"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: AdminInterfaceExposedCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestDebugEndpointsEnabledCheck:
    """Tests for DebugEndpointsEnabledCheck."""

    @pytest.fixture()
    def check(self) -> DebugEndpointsEnabledCheck:
        return DebugEndpointsEnabledCheck()

    async def test_metadata_loads_correctly(self, check: DebugEndpointsEnabledCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard006"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: DebugEndpointsEnabledCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingInputSanitizationCheck:
    """Tests for MissingInputSanitizationCheck."""

    @pytest.fixture()
    def check(self) -> MissingInputSanitizationCheck:
        return MissingInputSanitizationCheck()

    async def test_metadata_loads_correctly(self, check: MissingInputSanitizationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard007"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: MissingInputSanitizationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestInsecureDefaultCredentialsCheck:
    """Tests for InsecureDefaultCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> InsecureDefaultCredentialsCheck:
        return InsecureDefaultCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: InsecureDefaultCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard008"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: InsecureDefaultCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingSecurityUpdatesCheck:
    """Tests for MissingSecurityUpdatesCheck."""

    @pytest.fixture()
    def check(self) -> MissingSecurityUpdatesCheck:
        return MissingSecurityUpdatesCheck()

    async def test_metadata_loads_correctly(self, check: MissingSecurityUpdatesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard009"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: MissingSecurityUpdatesCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestExposedVersionInformationCheck:
    """Tests for ExposedVersionInformationCheck."""

    @pytest.fixture()
    def check(self) -> ExposedVersionInformationCheck:
        return ExposedVersionInformationCheck()

    async def test_metadata_loads_correctly(self, check: ExposedVersionInformationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard010"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: ExposedVersionInformationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingResourceLimitsCheck:
    """Tests for MissingResourceLimitsCheck."""

    @pytest.fixture()
    def check(self) -> MissingResourceLimitsCheck:
        return MissingResourceLimitsCheck()

    async def test_metadata_loads_correctly(self, check: MissingResourceLimitsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard011"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: MissingResourceLimitsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestUnnecessaryHttpMethodsCheck:
    """Tests for UnnecessaryHttpMethodsCheck."""

    @pytest.fixture()
    def check(self) -> UnnecessaryHttpMethodsCheck:
        return UnnecessaryHttpMethodsCheck()

    async def test_metadata_loads_correctly(self, check: UnnecessaryHttpMethodsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard012"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: UnnecessaryHttpMethodsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingRequestValidationCheck:
    """Tests for MissingRequestValidationCheck."""

    @pytest.fixture()
    def check(self) -> MissingRequestValidationCheck:
        return MissingRequestValidationCheck()

    async def test_metadata_loads_correctly(self, check: MissingRequestValidationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard013"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: MissingRequestValidationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestInsecureFilePermissionsCheck:
    """Tests for InsecureFilePermissionsCheck."""

    @pytest.fixture()
    def check(self) -> InsecureFilePermissionsCheck:
        return InsecureFilePermissionsCheck()

    async def test_metadata_loads_correctly(self, check: InsecureFilePermissionsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard014"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: InsecureFilePermissionsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingNetworkSegmentationCheck:
    """Tests for MissingNetworkSegmentationCheck."""

    @pytest.fixture()
    def check(self) -> MissingNetworkSegmentationCheck:
        return MissingNetworkSegmentationCheck()

    async def test_metadata_loads_correctly(self, check: MissingNetworkSegmentationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard015"
        assert meta.category == "server_hardening"

    async def test_stub_returns_empty(self, check: MissingNetworkSegmentationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


# ==========================================================================
# HARD-016: Debug Mode Indicators
# ==========================================================================


class TestDebugModeCheck:
    """Tests for DebugModeCheck."""

    @pytest.fixture()
    def check(self) -> DebugModeCheck:
        return DebugModeCheck()

    async def test_metadata_loads_correctly(self, check: DebugModeCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard016"
        assert meta.category == "server_hardening"

    async def test_fails_on_debug_env_true(self, check: DebugModeCheck) -> None:
        snapshot = make_snapshot(env={"DEBUG": "true"})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert "env:DEBUG=true" in fail_findings[0].evidence

    async def test_passes_on_debug_env_false(self, check: DebugModeCheck) -> None:
        snapshot = make_snapshot(env={"DEBUG": "false"})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) == 1

    async def test_fails_on_node_env_development(self, check: DebugModeCheck) -> None:
        snapshot = make_snapshot(env={"NODE_ENV": "development"})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1

    async def test_passes_on_node_env_production(self, check: DebugModeCheck) -> None:
        snapshot = make_snapshot(env={"NODE_ENV": "production"})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_fails_on_debug_arg(self, check: DebugModeCheck) -> None:
        snapshot = make_snapshot(args=["--debug", "server.js"])
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert "arg:--debug" in fail_findings[0].evidence

    async def test_fails_on_verbose_env(self, check: DebugModeCheck) -> None:
        snapshot = make_snapshot(env={"VERBOSE": "1"})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1

    async def test_empty_snapshot_returns_empty(self, check: DebugModeCheck) -> None:
        snapshot = make_snapshot(env={}, args=[], config_raw=None)
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# HARD-017: Permissive Server Capabilities
# ==========================================================================


class TestPermissiveCapabilitiesCheck:
    """Tests for PermissiveCapabilitiesCheck."""

    @pytest.fixture()
    def check(self) -> PermissiveCapabilitiesCheck:
        return PermissiveCapabilitiesCheck()

    async def test_metadata_loads_correctly(self, check: PermissiveCapabilitiesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard017"
        assert meta.category == "server_hardening"

    async def test_fails_on_all_capabilities_enabled(
        self, check: PermissiveCapabilitiesCheck
    ) -> None:
        snapshot = make_snapshot(
            capabilities={
                "tools": {"listChanged": True},
                "resources": {"subscribe": True},
                "prompts": {"listChanged": True},
                "sampling": {"enabled": True},
                "logging": {"enabled": True},
            }
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert "5" in fail_findings[0].status_extended
        assert "least privilege" in fail_findings[0].status_extended.lower()

    async def test_passes_on_subset_of_capabilities(
        self, check: PermissiveCapabilitiesCheck
    ) -> None:
        snapshot = make_snapshot(
            capabilities={
                "tools": {"listChanged": True},
                "resources": {"subscribe": True},
            }
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) == 1

    async def test_passes_on_single_capability(self, check: PermissiveCapabilitiesCheck) -> None:
        snapshot = make_snapshot(capabilities={"tools": {"listChanged": True}})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_empty_capabilities_returns_empty(
        self, check: PermissiveCapabilitiesCheck
    ) -> None:
        snapshot = make_snapshot(capabilities={})
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# HARD-018: Unrestricted Tool Execution Scope
# ==========================================================================


class TestUnrestrictedExecutionScopeCheck:
    """Tests for UnrestrictedExecutionScopeCheck."""

    @pytest.fixture()
    def check(self) -> UnrestrictedExecutionScopeCheck:
        return UnrestrictedExecutionScopeCheck()

    async def test_metadata_loads_correctly(self, check: UnrestrictedExecutionScopeCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "hard018"
        assert meta.category == "server_hardening"

    async def test_fails_on_privileged_and_exfiltrative_tools(
        self, check: UnrestrictedExecutionScopeCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "exec_shell",
                    "description": "Execute a shell command.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "send_email",
                    "description": "Send an email message.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert "privileged" in fail_findings[0].status_extended.lower()
        assert "exfiltrative" in fail_findings[0].status_extended.lower()

    async def test_passes_on_read_only_tools(self, check: UnrestrictedExecutionScopeCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "read_file",
                    "description": "Read a file from disk.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "list_items",
                    "description": "List items in a directory.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) == 1

    async def test_passes_on_only_privileged_tools(
        self, check: UnrestrictedExecutionScopeCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "exec_command",
                    "description": "Execute a system command.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_passes_on_only_exfiltrative_tools(
        self, check: UnrestrictedExecutionScopeCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "send_email",
                    "description": "Send an email.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_empty_tools_returns_empty(self, check: UnrestrictedExecutionScopeCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []
