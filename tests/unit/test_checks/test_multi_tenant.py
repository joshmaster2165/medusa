"""Unit tests for Multi Tenant checks (mt001-mt010)."""

from __future__ import annotations

import pytest

from medusa.checks.multi_tenant.mt001_missing_tenant_isolation import MissingTenantIsolationCheck
from medusa.checks.multi_tenant.mt002_shared_resource_access import SharedResourceAccessCheck
from medusa.checks.multi_tenant.mt003_tenant_data_leakage import TenantDataLeakageCheck
from medusa.checks.multi_tenant.mt004_missing_tenant_context import MissingTenantContextCheck
from medusa.checks.multi_tenant.mt005_tenant_impersonation import TenantImpersonationCheck
from medusa.checks.multi_tenant.mt006_shared_credential_store import SharedCredentialStoreCheck
from medusa.checks.multi_tenant.mt007_missing_tenant_audit import MissingTenantAuditCheck
from medusa.checks.multi_tenant.mt008_tenant_resource_exhaustion import (
    TenantResourceExhaustionCheck,
)
from medusa.checks.multi_tenant.mt009_cross_tenant_tool_access import CrossTenantToolAccessCheck
from medusa.checks.multi_tenant.mt010_missing_tenant_configuration import (
    MissingTenantConfigurationCheck,
)
from medusa.core.models import Status
from tests.conftest import make_snapshot

# ==========================================================================
# MT-001: Missing Tenant Isolation
# ==========================================================================


class TestMissingTenantIsolationCheck:
    """Tests for MissingTenantIsolationCheck."""

    @pytest.fixture()
    def check(self) -> MissingTenantIsolationCheck:
        return MissingTenantIsolationCheck()

    async def test_metadata_loads_correctly(self, check: MissingTenantIsolationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "mt001"
        assert meta.category == "multi_tenant"

    async def test_returns_empty_no_tools(self, check: MissingTenantIsolationCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_data_access_tool_without_tenant_param(
        self, check: MissingTenantIsolationCheck
    ) -> None:
        """Data-access tool without tenant_id param should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_records",
                    "description": "Fetch database records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Data-access tool without tenant param should FAIL"
        assert "get_records" in fail_findings[0].status_extended

    async def test_fails_on_destructive_tool_without_tenant_param(
        self, check: MissingTenantIsolationCheck
    ) -> None:
        """Destructive tool without tenant_id param should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_records",
                    "description": "Delete database records permanently.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "filter": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Destructive tool without tenant param should FAIL"

    async def test_passes_with_tenant_id_param(self, check: MissingTenantIsolationCheck) -> None:
        """Data-access tool with tenant_id param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_records",
                    "description": "Fetch database records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "tenant_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with tenant_id should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_with_workspace_id_param(self, check: MissingTenantIsolationCheck) -> None:
        """Data-access tool with workspace_id param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_records",
                    "description": "Fetch database records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "workspace_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with workspace_id should PASS"

    async def test_config_mitigates(self, check: MissingTenantIsolationCheck) -> None:
        """Config-level tenant isolation should mitigate missing param."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_records",
                    "description": "Fetch database records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                    },
                }
            ],
            config_raw={"command": "node", "tenant_isolation": True},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config tenant_isolation should mitigate"

    async def test_per_tool_findings(self, check: MissingTenantIsolationCheck) -> None:
        """Multiple data-access tools without tenant params should each get FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_records",
                    "description": "Fetch database records.",
                    "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
                },
                {
                    "name": "delete_records",
                    "description": "Delete database records permanently.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 2, "Each data-access tool should get its own FAIL"


# ==========================================================================
# MT-002: Shared Resource Access
# ==========================================================================


class TestSharedResourceAccessCheck:
    """Tests for SharedResourceAccessCheck."""

    @pytest.fixture()
    def check(self) -> SharedResourceAccessCheck:
        return SharedResourceAccessCheck()

    async def test_metadata_loads_correctly(self, check: SharedResourceAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "mt002"
        assert meta.category == "multi_tenant"

    async def test_returns_empty_no_tools_or_resources(
        self, check: SharedResourceAccessCheck
    ) -> None:
        """Empty tools and resources should return no findings."""
        snapshot = make_snapshot(tools=[], resources=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_resource_without_tenant_uri(
        self, check: SharedResourceAccessCheck
    ) -> None:
        """Resource without tenant-scoped URI should FAIL."""
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "file:///app/data/shared/users.json",
                    "name": "User Data",
                    "description": "All user records.",
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Resource without tenant URI should FAIL"

    async def test_passes_on_resource_with_tenant_uri(
        self, check: SharedResourceAccessCheck
    ) -> None:
        """Resource with tenant-scoped URI template should PASS."""
        snapshot = make_snapshot(
            resources=[
                {
                    "uriTemplate": "file:///app/data/{tenant_id}/users.json",
                    "name": "User Data",
                    "description": "Tenant-scoped user records.",
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Resource with tenant URI should PASS"

    async def test_fails_on_tool_without_tenant_param(
        self, check: SharedResourceAccessCheck
    ) -> None:
        """Data-access tool without tenant-scoping param should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_records",
                    "description": "Fetch database records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Data-access tool without tenant param should FAIL"

    async def test_passes_on_tool_with_tenant_param(self, check: SharedResourceAccessCheck) -> None:
        """Data-access tool with tenant_id param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_records",
                    "description": "Fetch database records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "tenant_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_config_mitigates(self, check: SharedResourceAccessCheck) -> None:
        """Config-level resource access control should mitigate."""
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "file:///app/data/shared/users.json",
                    "name": "User Data",
                }
            ],
            config_raw={"access_control": {"enabled": True}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config access_control should mitigate"


# ==========================================================================
# MT-003: Tenant Data Leakage
# ==========================================================================


class TestTenantDataLeakageCheck:
    """Tests for TenantDataLeakageCheck."""

    @pytest.fixture()
    def check(self) -> TenantDataLeakageCheck:
        return TenantDataLeakageCheck()

    async def test_metadata_loads_correctly(self, check: TenantDataLeakageCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "mt003"
        assert meta.category == "multi_tenant"

    async def test_returns_empty_no_tools(self, check: TenantDataLeakageCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_read_only_tool_without_tenant_param(
        self, check: TenantDataLeakageCheck
    ) -> None:
        """READ_ONLY tool without tenant param should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_users",
                    "description": "Retrieve all user records from the database.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"filter": {"type": "string"}},
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "READ_ONLY tool without tenant param should FAIL"

    async def test_fails_on_exfiltrative_tool_without_tenant_param(
        self, check: TenantDataLeakageCheck
    ) -> None:
        """EXFILTRATIVE tool without tenant param should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "export_users",
                    "description": "Export all user data.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"format": {"type": "string"}},
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "EXFILTRATIVE tool without tenant param should FAIL"

    async def test_passes_with_tenant_param(self, check: TenantDataLeakageCheck) -> None:
        """Data-reading tool with tenant_id param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_users",
                    "description": "Retrieve user records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "filter": {"type": "string"},
                            "tenant_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with tenant_id should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_skips_destructive_tool(self, check: TenantDataLeakageCheck) -> None:
        """DESTRUCTIVE tool should not trigger data leakage check."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Delete a user permanently.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        findings = await check.execute(snapshot)
        # Destructive tools are not in _LEAKAGE_RISKS, so no FAIL
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_config_mitigates(self, check: TenantDataLeakageCheck) -> None:
        """Config-level data isolation should mitigate."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_users",
                    "description": "Retrieve user records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"filter": {"type": "string"}},
                    },
                }
            ],
            config_raw={"row_level_security": True},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config RLS should mitigate data leakage"


# ==========================================================================
# MT-004: Missing Tenant Context
# ==========================================================================


class TestMissingTenantContextCheck:
    """Tests for MissingTenantContextCheck."""

    @pytest.fixture()
    def check(self) -> MissingTenantContextCheck:
        return MissingTenantContextCheck()

    async def test_metadata_loads_correctly(self, check: MissingTenantContextCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "mt004"
        assert meta.category == "multi_tenant"

    async def test_returns_empty_no_tools(self, check: MissingTenantContextCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_multi_tenant_description_without_tenant_param(
        self, check: MissingTenantContextCheck
    ) -> None:
        """Tool description mentioning 'tenant' without tenant param should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_data",
                    "description": "Retrieve data for the current tenant workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"filter": {"type": "string"}},
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Multi-tenant description without tenant param should FAIL"

    async def test_passes_with_tenant_param(self, check: MissingTenantContextCheck) -> None:
        """Tool with tenant keywords in description AND tenant_id param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_data",
                    "description": "Retrieve data for the current tenant workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "filter": {"type": "string"},
                            "tenant_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with tenant_id should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_skips_non_tenant_tool(self, check: MissingTenantContextCheck) -> None:
        """Tool with no tenant keywords in description should not trigger FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Fetch weather data for a city.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_config_mitigates(self, check: MissingTenantContextCheck) -> None:
        """Config-level tenant context validation should mitigate."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_data",
                    "description": "Retrieve data for the current tenant workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"filter": {"type": "string"}},
                    },
                }
            ],
            config_raw={"validate_tenant": True},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config validate_tenant should mitigate"


# ==========================================================================
# MT-005: Tenant Impersonation
# ==========================================================================


class TestTenantImpersonationCheck:
    """Tests for TenantImpersonationCheck."""

    @pytest.fixture()
    def check(self) -> TenantImpersonationCheck:
        return TenantImpersonationCheck()

    async def test_metadata_loads_correctly(self, check: TenantImpersonationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "mt005"
        assert meta.category == "multi_tenant"

    async def test_returns_empty_no_tools(self, check: TenantImpersonationCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_auth_tool_with_tenant_switch_no_reauth(
        self, check: TenantImpersonationCheck
    ) -> None:
        """Auth tool accepting tenant_id without reauth param should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "switch_auth_session",
                    "description": "Switch the active authentication session to another tenant.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "tenant_id": {"type": "string"},
                            "session_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Auth tool with tenant switch but no reauth should FAIL"

    async def test_passes_with_reauth_param(self, check: TenantImpersonationCheck) -> None:
        """Auth tool with tenant switch AND password/MFA param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "switch_auth_session",
                    "description": "Switch the active authentication session.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "tenant_id": {"type": "string"},
                            "password": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Auth tool with reauth param should PASS"

    async def test_skips_non_auth_tool(self, check: TenantImpersonationCheck) -> None:
        """Non-auth tool with tenant_id should not trigger impersonation check."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_records",
                    "description": "Fetch database records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "tenant_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_passes_auth_tool_without_tenant_param(
        self, check: TenantImpersonationCheck
    ) -> None:
        """Auth tool without tenant-switching param should PASS (no switch possible)."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "login",
                    "description": "Authenticate a user.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "username": {"type": "string"},
                            "password": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_config_mitigates(self, check: TenantImpersonationCheck) -> None:
        """Config-level impersonation prevention should mitigate."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "switch_auth_session",
                    "description": "Switch the active authentication session.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "tenant_id": {"type": "string"},
                        },
                    },
                }
            ],
            config_raw={"prevent_tenant_switch": True},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config prevent_tenant_switch should mitigate"


# ==========================================================================
# MT-006: Shared Credential Store
# ==========================================================================


class TestSharedCredentialStoreCheck:
    """Tests for SharedCredentialStoreCheck."""

    @pytest.fixture()
    def check(self) -> SharedCredentialStoreCheck:
        return SharedCredentialStoreCheck()

    async def test_metadata_loads_correctly(self, check: SharedCredentialStoreCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "mt006"
        assert meta.category == "multi_tenant"

    async def test_returns_empty_no_tools(self, check: SharedCredentialStoreCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_credential_tool_without_tenant_param(
        self, check: SharedCredentialStoreCheck
    ) -> None:
        """Credential-handling tool without tenant param should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_secret",
                    "description": "Retrieve a secret credential from the vault.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key_name": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Credential tool without tenant param should FAIL"

    async def test_passes_with_tenant_param(self, check: SharedCredentialStoreCheck) -> None:
        """Credential tool with tenant_id param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_secret",
                    "description": "Retrieve a secret credential from the vault.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key_name": {"type": "string"},
                            "tenant_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Credential tool with tenant_id should PASS"

    async def test_skips_non_credential_tool(self, check: SharedCredentialStoreCheck) -> None:
        """Non-credential tool should not trigger credential store check."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Fetch weather data.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_config_mitigates(self, check: SharedCredentialStoreCheck) -> None:
        """Config-level per-tenant credential isolation should mitigate."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_secret",
                    "description": "Retrieve a secret credential from the vault.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"key_name": {"type": "string"}},
                    },
                }
            ],
            config_raw={"credential_isolation": True},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config credential_isolation should mitigate"


# ==========================================================================
# MT-007: Missing Tenant Audit
# ==========================================================================


class TestMissingTenantAuditCheck:
    """Tests for MissingTenantAuditCheck."""

    @pytest.fixture()
    def check(self) -> MissingTenantAuditCheck:
        return MissingTenantAuditCheck()

    async def test_metadata_loads_correctly(self, check: MissingTenantAuditCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "mt007"
        assert meta.category == "multi_tenant"

    async def test_returns_empty_no_tools(self, check: MissingTenantAuditCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_when_no_audit_tools_exist(self, check: MissingTenantAuditCheck) -> None:
        """Server with tools but no audit/logging tool should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Fetch weather data.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "delete_user",
                    "description": "Delete a user.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "No audit tools at all should FAIL"

    async def test_fails_on_audit_tool_without_tenant_param(
        self, check: MissingTenantAuditCheck
    ) -> None:
        """Audit tool without tenant param should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_audit_log",
                    "description": "Retrieve the audit log entries.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "start_date": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Audit tool without tenant param should FAIL"

    async def test_passes_with_audit_tool_and_tenant_param(
        self, check: MissingTenantAuditCheck
    ) -> None:
        """Audit tool with tenant_id param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_audit_log",
                    "description": "Retrieve the audit log entries.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "start_date": {"type": "string"},
                            "tenant_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Audit tool with tenant_id should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_config_mitigates(self, check: MissingTenantAuditCheck) -> None:
        """Config-level tenant audit logging should mitigate."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Fetch weather data.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
            config_raw={"tenant_audit": True},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config tenant_audit should mitigate"


# ==========================================================================
# MT-008: Tenant Resource Exhaustion
# ==========================================================================


class TestTenantResourceExhaustionCheck:
    """Tests for TenantResourceExhaustionCheck."""

    @pytest.fixture()
    def check(self) -> TenantResourceExhaustionCheck:
        return TenantResourceExhaustionCheck()

    async def test_metadata_loads_correctly(self, check: TenantResourceExhaustionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "mt008"
        assert meta.category == "multi_tenant"

    async def test_returns_empty_no_tools(self, check: TenantResourceExhaustionCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_privileged_tool_without_tenant_or_limit(
        self, check: TenantResourceExhaustionCheck
    ) -> None:
        """Privileged tool without tenant/limit params should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "run_command",
                    "description": "Execute a shell command on the server.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "cmd": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Privileged tool without tenant/limit should FAIL"

    async def test_fails_on_resource_intensive_tool_without_limits(
        self, check: TenantResourceExhaustionCheck
    ) -> None:
        """Resource-intensive tool without limits should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "bulk_export",
                    "description": "Export all records in bulk from the database.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"format": {"type": "string"}},
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Resource-intensive tool without limits should FAIL"

    async def test_passes_with_tenant_param(self, check: TenantResourceExhaustionCheck) -> None:
        """Privileged tool with tenant_id param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "run_command",
                    "description": "Execute a shell command on the server.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "cmd": {"type": "string"},
                            "tenant_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with tenant_id should PASS"

    async def test_passes_with_limit_param(self, check: TenantResourceExhaustionCheck) -> None:
        """Resource-intensive tool with limit param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "bulk_export",
                    "description": "Export all records in bulk.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "format": {"type": "string"},
                            "limit": {"type": "integer"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with limit param should PASS"

    async def test_config_mitigates(self, check: TenantResourceExhaustionCheck) -> None:
        """Config-level tenant quota should mitigate."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "run_command",
                    "description": "Execute a shell command on the server.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"cmd": {"type": "string"}},
                    },
                }
            ],
            config_raw={"tenant_quota": {"cpu": 10, "memory": "1G"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config tenant_quota should mitigate"


# ==========================================================================
# MT-009: Cross-Tenant Tool Access
# ==========================================================================


class TestCrossTenantToolAccessCheck:
    """Tests for CrossTenantToolAccessCheck."""

    @pytest.fixture()
    def check(self) -> CrossTenantToolAccessCheck:
        return CrossTenantToolAccessCheck()

    async def test_metadata_loads_correctly(self, check: CrossTenantToolAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "mt009"
        assert meta.category == "multi_tenant"

    async def test_returns_empty_no_tools(self, check: CrossTenantToolAccessCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_dispatch_tool_without_tenant_param(
        self, check: CrossTenantToolAccessCheck
    ) -> None:
        """Tool with dispatch params (tool_name) but no tenant scoping should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "invoke_action",
                    "description": "Execute an action by name.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "tool_name": {"type": "string"},
                            "args": {"type": "object"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Dispatch tool without tenant param should FAIL"

    async def test_fails_on_powerful_tool_in_large_server(
        self, check: CrossTenantToolAccessCheck
    ) -> None:
        """Destructive tool without tenant param in server with 5+ tools should FAIL."""
        tools = [
            {
                "name": f"tool_{i}",
                "description": f"Tool {i} for data management.",
                "inputSchema": {"type": "object", "properties": {}},
            }
            for i in range(4)
        ]
        # Add a destructive tool without tenant param
        tools.append(
            {
                "name": "delete_records",
                "description": "Delete database records permanently.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"filter": {"type": "string"}},
                },
            }
        )
        snapshot = make_snapshot(tools=tools)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Powerful tool in large server without tenant should FAIL"

    async def test_passes_with_tenant_param_on_dispatch_tool(
        self, check: CrossTenantToolAccessCheck
    ) -> None:
        """Dispatch tool with tenant_id param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "invoke_action",
                    "description": "Execute an action by name.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "tool_name": {"type": "string"},
                            "tenant_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Dispatch tool with tenant_id should PASS"

    async def test_passes_on_safe_tools_small_server(
        self, check: CrossTenantToolAccessCheck
    ) -> None:
        """Safe tools in a small server (< 5 tools) should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Fetch weather data.",
                    "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_config_mitigates(self, check: CrossTenantToolAccessCheck) -> None:
        """Config-level tool access policy should mitigate."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "invoke_action",
                    "description": "Execute an action by name.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"tool_name": {"type": "string"}},
                    },
                }
            ],
            config_raw={"tool_access_policy": {"deny": ["*"]}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config tool_access_policy should mitigate"


# ==========================================================================
# MT-010: Missing Tenant Configuration
# ==========================================================================


class TestMissingTenantConfigurationCheck:
    """Tests for MissingTenantConfigurationCheck."""

    @pytest.fixture()
    def check(self) -> MissingTenantConfigurationCheck:
        return MissingTenantConfigurationCheck()

    async def test_metadata_loads_correctly(self, check: MissingTenantConfigurationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "mt010"
        assert meta.category == "multi_tenant"

    async def test_returns_empty_no_tools(self, check: MissingTenantConfigurationCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_config_tool_without_tenant_param(
        self, check: MissingTenantConfigurationCheck
    ) -> None:
        """Config management tool without tenant param should FAIL.

        Tool must be classified as a data-access risk AND match config keywords.
        Using 'get_setting' (READ_ONLY due to 'get') to ensure proper risk classification.
        """
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_setting",
                    "description": "Retrieve a configuration setting for the application.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Config tool without tenant param should FAIL"

    async def test_fails_on_feature_flag_tool_without_tenant(
        self, check: MissingTenantConfigurationCheck
    ) -> None:
        """Feature flag tool without tenant param should FAIL.

        Using 'delete_feature_flag' to ensure DESTRUCTIVE risk classification.
        """
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_feature_flag",
                    "description": "Remove a feature_flag permanently.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "flag_name": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Feature flag tool without tenant should FAIL"

    async def test_passes_with_tenant_param(self, check: MissingTenantConfigurationCheck) -> None:
        """Config tool with tenant_id param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_setting",
                    "description": "Retrieve a configuration setting.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string"},
                            "tenant_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config tool with tenant_id should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_skips_non_config_tool(self, check: MissingTenantConfigurationCheck) -> None:
        """Non-config tool should not trigger config isolation check."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Fetch weather data for a city.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_config_mitigates(self, check: MissingTenantConfigurationCheck) -> None:
        """Config-level tenant config isolation should mitigate."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_setting",
                    "description": "Retrieve a configuration setting.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"key": {"type": "string"}},
                    },
                }
            ],
            config_raw={"per_tenant_config": True},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config per_tenant_config should mitigate"
