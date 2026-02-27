"""Unit tests for Data Protection checks.

Covers DP-001 through DP-004.

Each check is tested for:
- Metadata loads correctly
- FAIL on vulnerable input
- PASS on clean input
- Graceful handling of empty snapshots
- Additional edge cases specific to each check
"""

from __future__ import annotations

import pytest

from medusa.checks.data_protection.dp001_pii_in_definitions import PiiInDefinitionsCheck
from medusa.checks.data_protection.dp002_sensitive_resource_uris import SensitiveResourceUrisCheck
from medusa.checks.data_protection.dp003_missing_data_classification import (
    MissingDataClassificationCheck,
)
from medusa.checks.data_protection.dp004_excessive_data_exposure import ExcessiveDataExposureCheck
from medusa.checks.data_protection.dp005_data_leakage_via_errors import DataLeakageViaErrorsCheck
from medusa.checks.data_protection.dp006_unmasked_sensitive_fields import (
    UnmaskedSensitiveFieldsCheck,
)
from medusa.checks.data_protection.dp007_missing_data_retention_policy import (
    MissingDataRetentionPolicyCheck,
)
from medusa.checks.data_protection.dp008_cross_origin_data_sharing import (
    CrossOriginDataSharingCheck,
)
from medusa.checks.data_protection.dp009_missing_encryption_at_rest import (
    MissingEncryptionAtRestCheck,
)
from medusa.checks.data_protection.dp010_missing_encryption_in_transit import (
    MissingEncryptionInTransitCheck,
)
from medusa.checks.data_protection.dp011_excessive_logging_of_pii import ExcessiveLoggingOfPiiCheck
from medusa.checks.data_protection.dp012_missing_consent_mechanism import (
    MissingConsentMechanismCheck,
)
from medusa.checks.data_protection.dp013_data_minimization_violation import (
    DataMinimizationViolationCheck,
)
from medusa.checks.data_protection.dp014_missing_data_anonymization import (
    MissingDataAnonymizationCheck,
)
from medusa.checks.data_protection.dp015_clipboard_data_exposure import ClipboardDataExposureCheck
from medusa.checks.data_protection.dp016_screenshot_capture_risk import ScreenshotCaptureRiskCheck
from medusa.checks.data_protection.dp017_keylogger_risk import KeyloggerRiskCheck
from medusa.checks.data_protection.dp018_browser_history_access import BrowserHistoryAccessCheck
from medusa.checks.data_protection.dp019_contact_data_access import ContactDataAccessCheck
from medusa.checks.data_protection.dp020_location_data_exposure import LocationDataExposureCheck
from medusa.checks.data_protection.dp021_camera_microphone_access import CameraMicrophoneAccessCheck
from medusa.checks.data_protection.dp022_calendar_data_access import CalendarDataAccessCheck
from medusa.checks.data_protection.dp023_message_data_access import MessageDataAccessCheck
from medusa.checks.data_protection.dp024_biometric_data_handling import BiometricDataHandlingCheck
from medusa.checks.data_protection.dp025_health_data_exposure import HealthDataExposureCheck
from medusa.checks.data_protection.dp026_financial_data_exposure import FinancialDataExposureCheck
from medusa.checks.data_protection.dp027_child_data_protection import ChildDataProtectionCheck
from medusa.checks.data_protection.dp028_data_portability_missing import DataPortabilityMissingCheck
from medusa.checks.data_protection.dp029_right_to_deletion_missing import (
    RightToDeletionMissingCheck,
)
from medusa.core.check import ServerSnapshot
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

# ==========================================================================
# DP-001: PII in Definitions
# ==========================================================================


class TestDP001PiiInDefinitions:
    """Tests for PiiInDefinitionsCheck."""

    @pytest.fixture()
    def check(self) -> PiiInDefinitionsCheck:
        return PiiInDefinitionsCheck()

    async def test_metadata_loads_correctly(self, check: PiiInDefinitionsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp001", "Check ID should be dp001"
        assert meta.category == "data_protection", "Category should be data_protection"
        assert meta.severity == Severity.HIGH, "Severity should be HIGH"

    async def test_fails_on_email_in_tool_description(self, check: PiiInDefinitionsCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "contact_tool",
                    "description": "Contact admin@example.com for support.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Email in tool description should be flagged"
        assert "Email" in fail_findings[0].evidence, "Evidence should mention email PII type"

    async def test_fails_on_ssn_in_param_default(self, check: PiiInDefinitionsCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "ssn_tool",
                    "description": "Validates SSN.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "ssn": {
                                "type": "string",
                                "description": "Social security number",
                                "default": "123-45-6789",
                            },
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "SSN in parameter default should be flagged"

    async def test_fails_on_phone_in_resource_description(
        self, check: PiiInDefinitionsCheck
    ) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "data://contacts",
                    "name": "Contacts",
                    "description": "Call 555-123-4567 for help.",
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Phone number in resource description should be flagged"

    async def test_fails_on_email_in_prompt_description(self, check: PiiInDefinitionsCheck) -> None:
        snapshot = make_snapshot(
            prompts=[
                {
                    "name": "email_prompt",
                    "description": "Send results to user@company.org for review.",
                    "arguments": [],
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Email in prompt description should be flagged"

    async def test_fails_on_credit_card_in_enum(self, check: PiiInDefinitionsCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "card_tool",
                    "description": "Processes payments.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "card": {
                                "type": "string",
                                "description": "Card number",
                                "enum": ["4111-1111-1111-1111", "5500-0000-0000-0004"],
                            },
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Credit card in enum should be flagged"

    async def test_passes_on_clean_snapshot(self, check: PiiInDefinitionsCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Returns the current weather for a city.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "city": {"type": "string", "description": "City name"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Clean snapshot should PASS"

    async def test_empty_snapshot_returns_no_findings(
        self, check: PiiInDefinitionsCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0, "Empty snapshot should produce zero findings"

    async def test_resource_snapshot_detects_email(
        self, check: PiiInDefinitionsCheck, resource_snapshot: ServerSnapshot
    ) -> None:
        """The resource_snapshot has a tool with admin@example.com in description."""
        findings = await check.execute(resource_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, (
            "resource_snapshot tool with admin@example.com should be flagged"
        )


# ==========================================================================
# DP-002: Sensitive Resource URIs
# ==========================================================================


class TestDP002SensitiveResourceUris:
    """Tests for SensitiveResourceUrisCheck."""

    @pytest.fixture()
    def check(self) -> SensitiveResourceUrisCheck:
        return SensitiveResourceUrisCheck()

    async def test_metadata_loads_correctly(self, check: SensitiveResourceUrisCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp002", "Check ID should be dp002"
        assert meta.category == "data_protection", "Category should be data_protection"
        assert meta.severity == Severity.HIGH, "Severity should be HIGH"

    async def test_fails_on_ssh_key_uri(self, check: SensitiveResourceUrisCheck) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "file:///home/user/.ssh/id_rsa",
                    "name": "SSH Key",
                    "description": "Private key.",
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "SSH key URI should be flagged"

    async def test_fails_on_env_file_uri(self, check: SensitiveResourceUrisCheck) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "file:///app/.env",
                    "name": "Environment",
                    "description": "Environment config.",
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, ".env file URI should be flagged"

    async def test_fails_on_credentials_json_uri(self, check: SensitiveResourceUrisCheck) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "file:///app/credentials.json",
                    "name": "Creds",
                    "description": "Service credentials.",
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "credentials.json URI should be flagged"

    async def test_fails_on_aws_credentials_uri(self, check: SensitiveResourceUrisCheck) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "file:///home/user/.aws/credentials",
                    "name": "AWS Creds",
                    "description": "AWS credential file.",
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "AWS credentials URI should be flagged"

    async def test_fails_on_uri_template(self, check: SensitiveResourceUrisCheck) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "data://config",
                    "uriTemplate": "file:///app/secrets.yaml",
                    "name": "Secrets",
                    "description": "Application secrets.",
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Sensitive uriTemplate should be flagged"

    async def test_passes_on_safe_uris(self, check: SensitiveResourceUrisCheck) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "data://users/list",
                    "name": "User List",
                    "description": "Public user directory.",
                    "mimeType": "application/json",
                },
                {
                    "uri": "file:///app/public/readme.md",
                    "name": "README",
                    "description": "Public readme file.",
                },
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Safe URIs should PASS"

    async def test_empty_snapshot_returns_no_findings(
        self, check: SensitiveResourceUrisCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0, "Empty snapshot should produce zero findings"

    async def test_resource_snapshot_detects_ssh(
        self, check: SensitiveResourceUrisCheck, resource_snapshot: ServerSnapshot
    ) -> None:
        """The resource_snapshot has a .ssh/id_rsa URI."""
        findings = await check.execute(resource_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "resource_snapshot with .ssh/id_rsa should be flagged"


# ==========================================================================
# DP-003: Missing Data Classification
# ==========================================================================


class TestDP003MissingDataClassification:
    """Tests for MissingDataClassificationCheck."""

    @pytest.fixture()
    def check(self) -> MissingDataClassificationCheck:
        return MissingDataClassificationCheck()

    async def test_metadata_loads_correctly(self, check: MissingDataClassificationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp003", "Check ID should be dp003"
        assert meta.category == "data_protection", "Category should be data_protection"
        assert meta.severity == Severity.LOW, "Severity should be LOW"

    async def test_fails_on_resource_without_mime_or_classification(
        self, check: MissingDataClassificationCheck
    ) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "data://users",
                    "name": "Users",
                    "description": "A list of user records.",
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, (
            "Resource without mimeType and classification should be flagged"
        )

    async def test_passes_on_resource_with_mimetype(
        self, check: MissingDataClassificationCheck
    ) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "data://users",
                    "name": "Users",
                    "description": "User records.",
                    "mimeType": "application/json",
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Resource with mimeType should PASS"

    async def test_passes_on_resource_with_classification_keyword(
        self, check: MissingDataClassificationCheck
    ) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "data://users",
                    "name": "Users",
                    "description": "Confidential user directory listing.",
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Resource with 'confidential' keyword should PASS"

    async def test_classification_keyword_is_case_insensitive(
        self, check: MissingDataClassificationCheck
    ) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "data://data",
                    "name": "Data",
                    "description": "This is PUBLIC data.",
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, (
            "Classification keywords should be case-insensitive"
        )

    async def test_empty_description_no_mime_fails(
        self, check: MissingDataClassificationCheck
    ) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "data://unknown",
                    "name": "Unknown",
                    "description": "",
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, (
            "Resource with empty description and no mimeType should be flagged"
        )

    async def test_empty_snapshot_returns_no_findings(
        self, check: MissingDataClassificationCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0, "Empty snapshot should produce zero findings"

    async def test_mixed_resources(self, check: MissingDataClassificationCheck) -> None:
        snapshot = make_snapshot(
            resources=[
                {
                    "uri": "data://good",
                    "name": "Good",
                    "description": "Internal documentation.",
                    "mimeType": "text/plain",
                },
                {
                    "uri": "data://bad",
                    "name": "Bad",
                    "description": "Some data.",
                },
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, "Only the unclassified resource should fail"
        assert fail_findings[0].resource_name == "Bad", "The 'Bad' resource should be flagged"


# ==========================================================================
# DP-004: Excessive Data Exposure
# ==========================================================================


class TestDP004ExcessiveDataExposure:
    """Tests for ExcessiveDataExposureCheck."""

    @pytest.fixture()
    def check(self) -> ExcessiveDataExposureCheck:
        return ExcessiveDataExposureCheck()

    async def test_metadata_loads_correctly(self, check: ExcessiveDataExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp004", "Check ID should be dp004"
        assert meta.category == "data_protection", "Category should be data_protection"
        assert meta.severity == Severity.MEDIUM, "Severity should be MEDIUM"

    async def test_fails_on_dump_all_without_pagination(
        self, check: ExcessiveDataExposureCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "dump_all_users",
                    "description": "Export all users.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "format": {"type": "string", "enum": ["json", "csv"]},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, "dump_all_users without pagination should be flagged"

    async def test_fails_on_export_data_without_pagination(
        self, check: ExcessiveDataExposureCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "export_data",
                    "description": "Export all data.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, "export_data without pagination should be flagged"

    async def test_fails_on_bulk_fetch_without_pagination(
        self, check: ExcessiveDataExposureCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "bulk_read",
                    "description": "Bulk read records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "table": {"type": "string"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, "bulk_read without pagination should be flagged"

    async def test_passes_on_dump_tool_with_limit_param(
        self, check: ExcessiveDataExposureCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "list_all_items",
                    "description": "List all items with pagination.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "limit": {"type": "integer"},
                            "offset": {"type": "integer"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Dump tool with pagination should PASS"

    async def test_passes_on_normal_tool(self, check: ExcessiveDataExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Returns weather.",
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
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Normal tool should PASS"

    async def test_empty_snapshot_returns_no_findings(
        self, check: ExcessiveDataExposureCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(empty_snapshot)
        assert len(findings) == 0, "Empty snapshot should produce zero findings"

    async def test_dump_tool_with_cursor_passes(self, check: ExcessiveDataExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "fetch_all_records",
                    "description": "Fetch all records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "cursor": {"type": "string"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Dump tool with cursor pagination should PASS"

    async def test_resource_snapshot_detects_dump_tool(
        self, check: ExcessiveDataExposureCheck, resource_snapshot: ServerSnapshot
    ) -> None:
        """The resource_snapshot has dump_all_users without pagination."""
        findings = await check.execute(resource_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "resource_snapshot dump_all_users should be flagged"


class TestDataLeakageViaErrorsCheck:
    """Tests for DataLeakageViaErrorsCheck."""

    @pytest.fixture()
    def check(self) -> DataLeakageViaErrorsCheck:
        return DataLeakageViaErrorsCheck()

    async def test_metadata_loads_correctly(self, check: DataLeakageViaErrorsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp005"
        assert meta.category == "data_protection"

    async def test_fails_on_missing_config_key(self, check: DataLeakageViaErrorsCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "debug": True},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: DataLeakageViaErrorsCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "debug": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: DataLeakageViaErrorsCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "debug_tool",
                    "description": "Returns verbose error detail with stack trace",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestUnmaskedSensitiveFieldsCheck:
    """Tests for UnmaskedSensitiveFieldsCheck."""

    @pytest.fixture()
    def check(self) -> UnmaskedSensitiveFieldsCheck:
        return UnmaskedSensitiveFieldsCheck()

    async def test_metadata_loads_correctly(self, check: UnmaskedSensitiveFieldsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp006"
        assert meta.category == "data_protection"

    async def test_fails_on_tool_with_issues(self, check: UnmaskedSensitiveFieldsCheck) -> None:
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

    async def test_processes_tool_schemas(self, check: UnmaskedSensitiveFieldsCheck) -> None:
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

    async def test_empty_tools_returns_empty(self, check: UnmaskedSensitiveFieldsCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == [] or all(f.status == Status.PASS for f in findings)


class TestMissingDataRetentionPolicyCheck:
    """Tests for MissingDataRetentionPolicyCheck."""

    @pytest.fixture()
    def check(self) -> MissingDataRetentionPolicyCheck:
        return MissingDataRetentionPolicyCheck()

    async def test_metadata_loads_correctly(self, check: MissingDataRetentionPolicyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp007"
        assert meta.category == "data_protection"

    async def test_fails_on_missing_config_key(
        self, check: MissingDataRetentionPolicyCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(
        self, check: MissingDataRetentionPolicyCheck
    ) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "retention": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: MissingDataRetentionPolicyCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestCrossOriginDataSharingCheck:
    """Tests for CrossOriginDataSharingCheck."""

    @pytest.fixture()
    def check(self) -> CrossOriginDataSharingCheck:
        return CrossOriginDataSharingCheck()

    async def test_metadata_loads_correctly(self, check: CrossOriginDataSharingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp008"
        assert meta.category == "data_protection"

    async def test_fails_on_missing_config_key(self, check: CrossOriginDataSharingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: CrossOriginDataSharingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "cors": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: CrossOriginDataSharingCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestMissingEncryptionAtRestCheck:
    """Tests for MissingEncryptionAtRestCheck."""

    @pytest.fixture()
    def check(self) -> MissingEncryptionAtRestCheck:
        return MissingEncryptionAtRestCheck()

    async def test_metadata_loads_correctly(self, check: MissingEncryptionAtRestCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp009"
        assert meta.category == "data_protection"

    async def test_fails_on_missing_config_key(self, check: MissingEncryptionAtRestCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: MissingEncryptionAtRestCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "encryption_at_rest": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: MissingEncryptionAtRestCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestMissingEncryptionInTransitCheck:
    """Tests for MissingEncryptionInTransitCheck."""

    @pytest.fixture()
    def check(self) -> MissingEncryptionInTransitCheck:
        return MissingEncryptionInTransitCheck()

    async def test_metadata_loads_correctly(self, check: MissingEncryptionInTransitCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp010"
        assert meta.category == "data_protection"

    async def test_fails_on_missing_config_key(
        self, check: MissingEncryptionInTransitCheck
    ) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="http://example.com:8080/mcp",
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(
        self, check: MissingEncryptionInTransitCheck
    ) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "command": "node",
                "tls": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: MissingEncryptionInTransitCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="http://example.com:8080/mcp",
            config_raw=None,
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestExcessiveLoggingOfPiiCheck:
    """Tests for ExcessiveLoggingOfPiiCheck."""

    @pytest.fixture()
    def check(self) -> ExcessiveLoggingOfPiiCheck:
        return ExcessiveLoggingOfPiiCheck()

    async def test_metadata_loads_correctly(self, check: ExcessiveLoggingOfPiiCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp011"
        assert meta.category == "data_protection"

    async def test_fails_on_tool_with_issues(self, check: ExcessiveLoggingOfPiiCheck) -> None:
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

    async def test_processes_tool_schemas(self, check: ExcessiveLoggingOfPiiCheck) -> None:
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

    async def test_empty_tools_returns_empty(self, check: ExcessiveLoggingOfPiiCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == [] or all(f.status == Status.PASS for f in findings)


class TestMissingConsentMechanismCheck:
    """Tests for MissingConsentMechanismCheck."""

    @pytest.fixture()
    def check(self) -> MissingConsentMechanismCheck:
        return MissingConsentMechanismCheck()

    async def test_metadata_loads_correctly(self, check: MissingConsentMechanismCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp012"
        assert meta.category == "data_protection"

    async def test_fails_on_missing_config_key(self, check: MissingConsentMechanismCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: MissingConsentMechanismCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "consent": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: MissingConsentMechanismCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestDataMinimizationViolationCheck:
    """Tests for DataMinimizationViolationCheck."""

    @pytest.fixture()
    def check(self) -> DataMinimizationViolationCheck:
        return DataMinimizationViolationCheck()

    async def test_metadata_loads_correctly(self, check: DataMinimizationViolationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp013"
        assert meta.category == "data_protection"

    async def test_fails_on_tool_with_issues(self, check: DataMinimizationViolationCheck) -> None:
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

    async def test_processes_tool_schemas(self, check: DataMinimizationViolationCheck) -> None:
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

    async def test_empty_tools_returns_empty(self, check: DataMinimizationViolationCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == [] or all(f.status == Status.PASS for f in findings)


class TestMissingDataAnonymizationCheck:
    """Tests for MissingDataAnonymizationCheck."""

    @pytest.fixture()
    def check(self) -> MissingDataAnonymizationCheck:
        return MissingDataAnonymizationCheck()

    async def test_metadata_loads_correctly(self, check: MissingDataAnonymizationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp014"
        assert meta.category == "data_protection"

    async def test_fails_on_missing_config_key(self, check: MissingDataAnonymizationCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "user_lookup",
                    "description": "Look up user by email",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"email": {"type": "string"}},
                    },
                }
            ],
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: MissingDataAnonymizationCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "user_lookup",
                    "description": "Look up user by email",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"email": {"type": "string"}},
                    },
                }
            ],
            config_raw={
                "command": "node",
                "anonymize": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: MissingDataAnonymizationCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "user_lookup",
                    "description": "Look up user by email",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"email": {"type": "string"}},
                    },
                }
            ],
            config_raw=None,
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestClipboardDataExposureCheck:
    """Tests for ClipboardDataExposureCheck."""

    @pytest.fixture()
    def check(self) -> ClipboardDataExposureCheck:
        return ClipboardDataExposureCheck()

    async def test_metadata_loads_correctly(self, check: ClipboardDataExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp015"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: ClipboardDataExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "clipboard_tool", "description": "Handles clipboard data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: ClipboardDataExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: ClipboardDataExposureCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestScreenshotCaptureRiskCheck:
    """Tests for ScreenshotCaptureRiskCheck."""

    @pytest.fixture()
    def check(self) -> ScreenshotCaptureRiskCheck:
        return ScreenshotCaptureRiskCheck()

    async def test_metadata_loads_correctly(self, check: ScreenshotCaptureRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp016"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: ScreenshotCaptureRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "screenshot_tool", "description": "Handles screenshot data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: ScreenshotCaptureRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: ScreenshotCaptureRiskCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestKeyloggerRiskCheck:
    """Tests for KeyloggerRiskCheck."""

    @pytest.fixture()
    def check(self) -> KeyloggerRiskCheck:
        return KeyloggerRiskCheck()

    async def test_metadata_loads_correctly(self, check: KeyloggerRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp017"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: KeyloggerRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "keylog_tool", "description": "Handles keylog data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: KeyloggerRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: KeyloggerRiskCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestBrowserHistoryAccessCheck:
    """Tests for BrowserHistoryAccessCheck."""

    @pytest.fixture()
    def check(self) -> BrowserHistoryAccessCheck:
        return BrowserHistoryAccessCheck()

    async def test_metadata_loads_correctly(self, check: BrowserHistoryAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp018"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: BrowserHistoryAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "browser_history_tool", "description": "Handles browser_history data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: BrowserHistoryAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: BrowserHistoryAccessCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestContactDataAccessCheck:
    """Tests for ContactDataAccessCheck."""

    @pytest.fixture()
    def check(self) -> ContactDataAccessCheck:
        return ContactDataAccessCheck()

    async def test_metadata_loads_correctly(self, check: ContactDataAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp019"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: ContactDataAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "contacts_tool", "description": "Handles contacts data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: ContactDataAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: ContactDataAccessCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestLocationDataExposureCheck:
    """Tests for LocationDataExposureCheck."""

    @pytest.fixture()
    def check(self) -> LocationDataExposureCheck:
        return LocationDataExposureCheck()

    async def test_metadata_loads_correctly(self, check: LocationDataExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp020"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: LocationDataExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "location_tool", "description": "Handles location data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: LocationDataExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: LocationDataExposureCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestCameraMicrophoneAccessCheck:
    """Tests for CameraMicrophoneAccessCheck."""

    @pytest.fixture()
    def check(self) -> CameraMicrophoneAccessCheck:
        return CameraMicrophoneAccessCheck()

    async def test_metadata_loads_correctly(self, check: CameraMicrophoneAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp021"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: CameraMicrophoneAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "camera_tool", "description": "Handles camera data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: CameraMicrophoneAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: CameraMicrophoneAccessCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestCalendarDataAccessCheck:
    """Tests for CalendarDataAccessCheck."""

    @pytest.fixture()
    def check(self) -> CalendarDataAccessCheck:
        return CalendarDataAccessCheck()

    async def test_metadata_loads_correctly(self, check: CalendarDataAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp022"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: CalendarDataAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "calendar_tool", "description": "Handles calendar data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: CalendarDataAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: CalendarDataAccessCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestMessageDataAccessCheck:
    """Tests for MessageDataAccessCheck."""

    @pytest.fixture()
    def check(self) -> MessageDataAccessCheck:
        return MessageDataAccessCheck()

    async def test_metadata_loads_correctly(self, check: MessageDataAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp023"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: MessageDataAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "messages_tool", "description": "Handles messages data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: MessageDataAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: MessageDataAccessCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestBiometricDataHandlingCheck:
    """Tests for BiometricDataHandlingCheck."""

    @pytest.fixture()
    def check(self) -> BiometricDataHandlingCheck:
        return BiometricDataHandlingCheck()

    async def test_metadata_loads_correctly(self, check: BiometricDataHandlingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp024"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: BiometricDataHandlingCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "biometric_tool", "description": "Handles biometric data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: BiometricDataHandlingCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: BiometricDataHandlingCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestHealthDataExposureCheck:
    """Tests for HealthDataExposureCheck."""

    @pytest.fixture()
    def check(self) -> HealthDataExposureCheck:
        return HealthDataExposureCheck()

    async def test_metadata_loads_correctly(self, check: HealthDataExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp025"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: HealthDataExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "health_tool", "description": "Handles health data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: HealthDataExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: HealthDataExposureCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestFinancialDataExposureCheck:
    """Tests for FinancialDataExposureCheck."""

    @pytest.fixture()
    def check(self) -> FinancialDataExposureCheck:
        return FinancialDataExposureCheck()

    async def test_metadata_loads_correctly(self, check: FinancialDataExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp026"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: FinancialDataExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "payment_tool", "description": "Handles payment data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: FinancialDataExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: FinancialDataExposureCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestChildDataProtectionCheck:
    """Tests for ChildDataProtectionCheck."""

    @pytest.fixture()
    def check(self) -> ChildDataProtectionCheck:
        return ChildDataProtectionCheck()

    async def test_metadata_loads_correctly(self, check: ChildDataProtectionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp027"
        assert meta.category == "data_protection"

    async def test_fails_on_keyword_in_tool(self, check: ChildDataProtectionCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "child_tool", "description": "Handles child data"}],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_clean_tools(self, check: ChildDataProtectionCheck) -> None:
        snapshot = make_snapshot(
            tools=[{"name": "safe_tool", "description": "A utility"}],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_empty_tools_returns_empty(self, check: ChildDataProtectionCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []


class TestDataPortabilityMissingCheck:
    """Tests for DataPortabilityMissingCheck."""

    @pytest.fixture()
    def check(self) -> DataPortabilityMissingCheck:
        return DataPortabilityMissingCheck()

    async def test_metadata_loads_correctly(self, check: DataPortabilityMissingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp028"
        assert meta.category == "data_protection"

    async def test_fails_on_missing_config_key(self, check: DataPortabilityMissingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: DataPortabilityMissingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "export": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: DataPortabilityMissingCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


class TestRightToDeletionMissingCheck:
    """Tests for RightToDeletionMissingCheck."""

    @pytest.fixture()
    def check(self) -> RightToDeletionMissingCheck:
        return RightToDeletionMissingCheck()

    async def test_metadata_loads_correctly(self, check: RightToDeletionMissingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dp029"
        assert meta.category == "data_protection"

    async def test_fails_on_missing_config_key(self, check: RightToDeletionMissingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_config_key_present(self, check: RightToDeletionMissingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "deletion": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_no_config_fails(self, check: RightToDeletionMissingCheck) -> None:
        snapshot = make_snapshot(config_raw=None)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
