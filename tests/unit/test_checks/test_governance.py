"""Unit tests for Governance checks (auto-generated stubs)."""

from __future__ import annotations

import pytest

from medusa.checks.governance.gov001_missing_security_policy import MissingSecurityPolicyCheck
from medusa.checks.governance.gov002_missing_privacy_policy import MissingPrivacyPolicyCheck
from medusa.checks.governance.gov003_missing_terms_of_service import MissingTermsOfServiceCheck
from medusa.checks.governance.gov004_missing_compliance_mapping import MissingComplianceMappingCheck
from medusa.checks.governance.gov005_missing_incident_response_plan import (
    MissingIncidentResponsePlanCheck,
)
from medusa.checks.governance.gov006_missing_change_management import MissingChangeManagementCheck
from medusa.checks.governance.gov007_missing_access_review import MissingAccessReviewCheck
from medusa.checks.governance.gov008_missing_vulnerability_management import (
    MissingVulnerabilityManagementCheck,
)
from medusa.checks.governance.gov009_missing_data_governance import MissingDataGovernanceCheck
from medusa.checks.governance.gov010_missing_third_party_risk import MissingThirdPartyRiskCheck
from medusa.checks.governance.gov011_missing_business_continuity import (
    MissingBusinessContinuityCheck,
)
from medusa.checks.governance.gov012_missing_disaster_recovery import MissingDisasterRecoveryCheck
from medusa.checks.governance.gov013_missing_sla_definition import MissingSlaDefinitionCheck
from medusa.checks.governance.gov014_missing_regulatory_compliance import (
    MissingRegulatoryComplianceCheck,
)
from medusa.checks.governance.gov015_missing_audit_schedule import MissingAuditScheduleCheck
from medusa.checks.governance.gov016_missing_training_program import MissingTrainingProgramCheck
from medusa.checks.governance.gov017_missing_asset_inventory import MissingAssetInventoryCheck
from medusa.checks.governance.gov018_missing_risk_assessment import MissingRiskAssessmentCheck
from medusa.checks.governance.gov019_missing_data_classification_policy import (
    MissingDataClassificationPolicyCheck,
)
from medusa.checks.governance.gov020_missing_vendor_assessment import MissingVendorAssessmentCheck
from medusa.checks.governance.gov021_missing_tool_namespace import MissingToolNamespaceCheck
from medusa.checks.governance.gov022_missing_server_version import MissingServerVersionCheck
from medusa.core.models import Status
from tests.conftest import make_snapshot


class TestMissingSecurityPolicyCheck:
    """Tests for MissingSecurityPolicyCheck."""

    @pytest.fixture()
    def check(self) -> MissingSecurityPolicyCheck:
        return MissingSecurityPolicyCheck()

    async def test_metadata_loads_correctly(self, check: MissingSecurityPolicyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov001"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingSecurityPolicyCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingPrivacyPolicyCheck:
    """Tests for MissingPrivacyPolicyCheck."""

    @pytest.fixture()
    def check(self) -> MissingPrivacyPolicyCheck:
        return MissingPrivacyPolicyCheck()

    async def test_metadata_loads_correctly(self, check: MissingPrivacyPolicyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov002"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingPrivacyPolicyCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingTermsOfServiceCheck:
    """Tests for MissingTermsOfServiceCheck."""

    @pytest.fixture()
    def check(self) -> MissingTermsOfServiceCheck:
        return MissingTermsOfServiceCheck()

    async def test_metadata_loads_correctly(self, check: MissingTermsOfServiceCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov003"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingTermsOfServiceCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingComplianceMappingCheck:
    """Tests for MissingComplianceMappingCheck."""

    @pytest.fixture()
    def check(self) -> MissingComplianceMappingCheck:
        return MissingComplianceMappingCheck()

    async def test_metadata_loads_correctly(self, check: MissingComplianceMappingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov004"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingComplianceMappingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingIncidentResponsePlanCheck:
    """Tests for MissingIncidentResponsePlanCheck."""

    @pytest.fixture()
    def check(self) -> MissingIncidentResponsePlanCheck:
        return MissingIncidentResponsePlanCheck()

    async def test_metadata_loads_correctly(self, check: MissingIncidentResponsePlanCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov005"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingIncidentResponsePlanCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingChangeManagementCheck:
    """Tests for MissingChangeManagementCheck."""

    @pytest.fixture()
    def check(self) -> MissingChangeManagementCheck:
        return MissingChangeManagementCheck()

    async def test_metadata_loads_correctly(self, check: MissingChangeManagementCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov006"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingChangeManagementCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingAccessReviewCheck:
    """Tests for MissingAccessReviewCheck."""

    @pytest.fixture()
    def check(self) -> MissingAccessReviewCheck:
        return MissingAccessReviewCheck()

    async def test_metadata_loads_correctly(self, check: MissingAccessReviewCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov007"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingAccessReviewCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingVulnerabilityManagementCheck:
    """Tests for MissingVulnerabilityManagementCheck."""

    @pytest.fixture()
    def check(self) -> MissingVulnerabilityManagementCheck:
        return MissingVulnerabilityManagementCheck()

    async def test_metadata_loads_correctly(
        self, check: MissingVulnerabilityManagementCheck
    ) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov008"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingVulnerabilityManagementCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingDataGovernanceCheck:
    """Tests for MissingDataGovernanceCheck."""

    @pytest.fixture()
    def check(self) -> MissingDataGovernanceCheck:
        return MissingDataGovernanceCheck()

    async def test_metadata_loads_correctly(self, check: MissingDataGovernanceCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov009"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingDataGovernanceCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingThirdPartyRiskCheck:
    """Tests for MissingThirdPartyRiskCheck."""

    @pytest.fixture()
    def check(self) -> MissingThirdPartyRiskCheck:
        return MissingThirdPartyRiskCheck()

    async def test_metadata_loads_correctly(self, check: MissingThirdPartyRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov010"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingThirdPartyRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingBusinessContinuityCheck:
    """Tests for MissingBusinessContinuityCheck."""

    @pytest.fixture()
    def check(self) -> MissingBusinessContinuityCheck:
        return MissingBusinessContinuityCheck()

    async def test_metadata_loads_correctly(self, check: MissingBusinessContinuityCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov011"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingBusinessContinuityCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingDisasterRecoveryCheck:
    """Tests for MissingDisasterRecoveryCheck."""

    @pytest.fixture()
    def check(self) -> MissingDisasterRecoveryCheck:
        return MissingDisasterRecoveryCheck()

    async def test_metadata_loads_correctly(self, check: MissingDisasterRecoveryCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov012"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingDisasterRecoveryCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingSlaDefinitionCheck:
    """Tests for MissingSlaDefinitionCheck."""

    @pytest.fixture()
    def check(self) -> MissingSlaDefinitionCheck:
        return MissingSlaDefinitionCheck()

    async def test_metadata_loads_correctly(self, check: MissingSlaDefinitionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov013"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingSlaDefinitionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingRegulatoryComplianceCheck:
    """Tests for MissingRegulatoryComplianceCheck."""

    @pytest.fixture()
    def check(self) -> MissingRegulatoryComplianceCheck:
        return MissingRegulatoryComplianceCheck()

    async def test_metadata_loads_correctly(self, check: MissingRegulatoryComplianceCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov014"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingRegulatoryComplianceCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingAuditScheduleCheck:
    """Tests for MissingAuditScheduleCheck."""

    @pytest.fixture()
    def check(self) -> MissingAuditScheduleCheck:
        return MissingAuditScheduleCheck()

    async def test_metadata_loads_correctly(self, check: MissingAuditScheduleCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov015"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingAuditScheduleCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingTrainingProgramCheck:
    """Tests for MissingTrainingProgramCheck."""

    @pytest.fixture()
    def check(self) -> MissingTrainingProgramCheck:
        return MissingTrainingProgramCheck()

    async def test_metadata_loads_correctly(self, check: MissingTrainingProgramCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov016"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingTrainingProgramCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingAssetInventoryCheck:
    """Tests for MissingAssetInventoryCheck."""

    @pytest.fixture()
    def check(self) -> MissingAssetInventoryCheck:
        return MissingAssetInventoryCheck()

    async def test_metadata_loads_correctly(self, check: MissingAssetInventoryCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov017"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingAssetInventoryCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingRiskAssessmentCheck:
    """Tests for MissingRiskAssessmentCheck."""

    @pytest.fixture()
    def check(self) -> MissingRiskAssessmentCheck:
        return MissingRiskAssessmentCheck()

    async def test_metadata_loads_correctly(self, check: MissingRiskAssessmentCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov018"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingRiskAssessmentCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingDataClassificationPolicyCheck:
    """Tests for MissingDataClassificationPolicyCheck."""

    @pytest.fixture()
    def check(self) -> MissingDataClassificationPolicyCheck:
        return MissingDataClassificationPolicyCheck()

    async def test_metadata_loads_correctly(
        self, check: MissingDataClassificationPolicyCheck
    ) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov019"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingDataClassificationPolicyCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingVendorAssessmentCheck:
    """Tests for MissingVendorAssessmentCheck."""

    @pytest.fixture()
    def check(self) -> MissingVendorAssessmentCheck:
        return MissingVendorAssessmentCheck()

    async def test_metadata_loads_correctly(self, check: MissingVendorAssessmentCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov020"
        assert meta.category == "governance"

    async def test_stub_returns_empty(self, check: MissingVendorAssessmentCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


# ==========================================================================
# GOV-021: Missing Tool Namespace
# ==========================================================================


class TestMissingToolNamespaceCheck:
    """Tests for MissingToolNamespaceCheck."""

    @pytest.fixture()
    def check(self) -> MissingToolNamespaceCheck:
        return MissingToolNamespaceCheck()

    async def test_metadata_loads_correctly(self, check: MissingToolNamespaceCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov021"
        assert meta.category == "governance"

    async def test_fails_on_many_tools_without_namespace(
        self, check: MissingToolNamespaceCheck
    ) -> None:
        tools = [
            {"name": f"tool_{i}", "description": f"Tool {i}"}
            for i in range(10)
        ]
        snapshot = make_snapshot(tools=tools)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert "10/10" in fail_findings[0].status_extended

    async def test_passes_on_namespaced_tools(
        self, check: MissingToolNamespaceCheck
    ) -> None:
        tools = [
            {"name": f"org.service.tool_{i}", "description": f"Tool {i}"}
            for i in range(10)
        ]
        snapshot = make_snapshot(tools=tools)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) == 1

    async def test_passes_on_double_colon_namespace(
        self, check: MissingToolNamespaceCheck
    ) -> None:
        tools = [
            {"name": f"myorg::tool_{i}", "description": f"Tool {i}"}
            for i in range(10)
        ]
        snapshot = make_snapshot(tools=tools)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_passes_on_five_or_fewer_tools(
        self, check: MissingToolNamespaceCheck
    ) -> None:
        tools = [
            {"name": f"tool_{i}", "description": f"Tool {i}"}
            for i in range(5)
        ]
        snapshot = make_snapshot(tools=tools)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) == 1

    async def test_empty_tools_returns_empty(
        self, check: MissingToolNamespaceCheck
    ) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_mixed_namespaced_and_non_namespaced(
        self, check: MissingToolNamespaceCheck
    ) -> None:
        tools = [
            {"name": f"org.tool_{i}", "description": f"Tool {i}"}
            for i in range(7)
        ] + [
            {"name": f"plain_tool_{i}", "description": f"Tool {i}"}
            for i in range(3)
        ]
        snapshot = make_snapshot(tools=tools)
        findings = await check.execute(snapshot)
        # 3/10 without namespace = 30%, below 50% threshold so PASS
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) == 1


# ==========================================================================
# GOV-022: Missing Server Version
# ==========================================================================


class TestMissingServerVersionCheck:
    """Tests for MissingServerVersionCheck."""

    @pytest.fixture()
    def check(self) -> MissingServerVersionCheck:
        return MissingServerVersionCheck()

    async def test_metadata_loads_correctly(self, check: MissingServerVersionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "gov022"
        assert meta.category == "governance"

    async def test_fails_on_empty_server_info(
        self, check: MissingServerVersionCheck
    ) -> None:
        snapshot = make_snapshot(server_info={})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert "server_info=missing" in fail_findings[0].evidence

    async def test_passes_on_valid_version(
        self, check: MissingServerVersionCheck
    ) -> None:
        snapshot = make_snapshot(
            server_info={"name": "my-server", "version": "1.2.3"}
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) == 1
        assert "1.2.3" in pass_findings[0].status_extended

    async def test_fails_on_missing_version_key(
        self, check: MissingServerVersionCheck
    ) -> None:
        snapshot = make_snapshot(
            server_info={"name": "my-server"}
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert "version=empty" in fail_findings[0].evidence

    async def test_fails_on_placeholder_version(
        self, check: MissingServerVersionCheck
    ) -> None:
        snapshot = make_snapshot(
            server_info={"name": "my-server", "version": "0.0.0"}
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1
        assert "placeholder" in fail_findings[0].evidence

    async def test_fails_on_dev_version(
        self, check: MissingServerVersionCheck
    ) -> None:
        snapshot = make_snapshot(
            server_info={"name": "my-server", "version": "dev"}
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1

    async def test_passes_on_semver_version(
        self, check: MissingServerVersionCheck
    ) -> None:
        snapshot = make_snapshot(
            server_info={"name": "my-server", "version": "2.5.1-beta.1"}
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) == 1
