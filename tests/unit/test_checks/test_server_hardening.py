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
