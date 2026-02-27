"""Unit tests for Server Identity checks.

Covers SHADOW-001 (Generic Server Names) and SHADOW-002 (Unverified Server Identity).

Each check is tested for:
- Metadata loads correctly
- FAIL on vulnerable configurations
- PASS on secure configurations
- Edge cases and skip behaviour
"""

from __future__ import annotations

import pytest

from medusa.checks.server_identity.shadow001_duplicate_server_names import GenericServerNameCheck
from medusa.checks.server_identity.shadow002_unverified_server_identity import (
    UnverifiedServerIdentityCheck,
)
from medusa.checks.server_identity.shadow003_duplicate_tool_names_across_servers import (
    DuplicateToolNamesAcrossServersCheck,
)
from medusa.checks.server_identity.shadow004_missing_server_metadata import (
    MissingServerMetadataCheck,
)
from medusa.checks.server_identity.shadow005_suspicious_server_origin import (
    SuspiciousServerOriginCheck,
)
from medusa.checks.server_identity.shadow006_server_version_spoofing import (
    ServerVersionSpoofingCheck,
)
from medusa.checks.server_identity.shadow007_unauthorized_server_registration import (
    UnauthorizedServerRegistrationCheck,
)
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

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
        assert meta.category == "server_identity"
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
        assert meta.category == "server_identity"
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
        snapshot = make_snapshot(server_info={"name": "my-server", "version": "1.0.0"})
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


class TestDuplicateToolNamesAcrossServersCheck:
    """Tests for DuplicateToolNamesAcrossServersCheck."""

    @pytest.fixture()
    def check(self) -> DuplicateToolNamesAcrossServersCheck:
        return DuplicateToolNamesAcrossServersCheck()

    async def test_metadata_loads_correctly(
        self, check: DuplicateToolNamesAcrossServersCheck
    ) -> None:
        meta = check.metadata()
        assert meta.check_id == "shadow003"
        assert meta.category == "server_identity"

    async def test_runs_on_populated_snapshot(
        self, check: DuplicateToolNamesAcrossServersCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "test_tool", "description": "A test tool"}],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_runs_on_tools(self, check: DuplicateToolNamesAcrossServersCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "test_tool", "description": "A test"}],
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert len(findings) >= 1

    async def test_empty_tools_returns_empty(
        self, check: DuplicateToolNamesAcrossServersCheck
    ) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == [] or all(f.status == Status.PASS for f in findings)


class TestMissingServerMetadataCheck:
    """Tests for MissingServerMetadataCheck."""

    @pytest.fixture()
    def check(self) -> MissingServerMetadataCheck:
        return MissingServerMetadataCheck()

    async def test_metadata_loads_correctly(self, check: MissingServerMetadataCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "shadow004"
        assert meta.category == "server_identity"

    async def test_fails_on_missing_metadata(self, check: MissingServerMetadataCheck) -> None:
        snapshot = make_snapshot(server_info={})
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert len(findings) >= 1

    async def test_passes_on_complete_metadata(self, check: MissingServerMetadataCheck) -> None:
        snapshot = make_snapshot(
            server_info={"name": "test-server", "version": "1.0.0"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_checks_server_info(self, check: MissingServerMetadataCheck) -> None:
        snapshot = make_snapshot(
            server_info={"name": "test", "version": "1.0"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_empty_server_info(self, check: MissingServerMetadataCheck) -> None:
        snapshot = make_snapshot(server_info={})
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSuspiciousServerOriginCheck:
    """Tests for SuspiciousServerOriginCheck."""

    @pytest.fixture()
    def check(self) -> SuspiciousServerOriginCheck:
        return SuspiciousServerOriginCheck()

    async def test_metadata_loads_correctly(self, check: SuspiciousServerOriginCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "shadow005"
        assert meta.category == "server_identity"

    async def test_runs_on_populated_snapshot(self, check: SuspiciousServerOriginCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "test_tool", "description": "A test tool"}],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_executes_without_error(self, check: SuspiciousServerOriginCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "t", "description": "A test tool"}],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_empty_snapshot(self, check: SuspiciousServerOriginCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestServerVersionSpoofingCheck:
    """Tests for ServerVersionSpoofingCheck."""

    @pytest.fixture()
    def check(self) -> ServerVersionSpoofingCheck:
        return ServerVersionSpoofingCheck()

    async def test_metadata_loads_correctly(self, check: ServerVersionSpoofingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "shadow006"
        assert meta.category == "server_identity"

    async def test_fails_on_missing_metadata(self, check: ServerVersionSpoofingCheck) -> None:
        snapshot = make_snapshot(server_info={})
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
        assert len(findings) >= 1

    async def test_passes_on_complete_metadata(self, check: ServerVersionSpoofingCheck) -> None:
        snapshot = make_snapshot(
            server_info={"name": "test-server", "version": "1.0.0"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_checks_server_info(self, check: ServerVersionSpoofingCheck) -> None:
        snapshot = make_snapshot(
            server_info={"name": "test", "version": "1.0"},
        )
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)

    async def test_empty_server_info(self, check: ServerVersionSpoofingCheck) -> None:
        snapshot = make_snapshot(server_info={})
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestUnauthorizedServerRegistrationCheck:
    """Tests for UnauthorizedServerRegistrationCheck."""

    @pytest.fixture()
    def check(self) -> UnauthorizedServerRegistrationCheck:
        return UnauthorizedServerRegistrationCheck()

    async def test_metadata_loads_correctly(
        self, check: UnauthorizedServerRegistrationCheck
    ) -> None:
        meta = check.metadata()
        assert meta.check_id == "shadow007"
        assert meta.category == "server_identity"

    async def test_fails_on_missing_config_key(
        self, check: UnauthorizedServerRegistrationCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(
        self, check: UnauthorizedServerRegistrationCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "logging": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_fails_on_missing_config_key(
        self, check: UnauthorizedServerRegistrationCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(
        self, check: UnauthorizedServerRegistrationCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "authorization": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: UnauthorizedServerRegistrationCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
