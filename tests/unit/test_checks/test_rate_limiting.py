"""Unit tests for Rate Limiting checks (auto-generated stubs)."""

from __future__ import annotations

import pytest

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import MissingRateLimitingCheck
from medusa.checks.rate_limiting.dos002_missing_request_throttling import (
    MissingRequestThrottlingCheck,
)
from medusa.checks.rate_limiting.dos003_resource_exhaustion_risk import ResourceExhaustionRiskCheck
from medusa.checks.rate_limiting.dos004_concurrent_request_limit import ConcurrentRequestLimitCheck
from medusa.checks.rate_limiting.dos005_payload_size_limit import PayloadSizeLimitCheck
from medusa.checks.rate_limiting.dos006_timeout_configuration import TimeoutConfigurationCheck
from medusa.checks.rate_limiting.dos007_connection_pool_exhaustion import (
    ConnectionPoolExhaustionCheck,
)
from medusa.checks.rate_limiting.dos008_memory_exhaustion_risk import MemoryExhaustionRiskCheck
from medusa.checks.rate_limiting.dos009_disk_exhaustion_risk import DiskExhaustionRiskCheck
from medusa.checks.rate_limiting.dos010_cpu_exhaustion_risk import CpuExhaustionRiskCheck
from medusa.checks.rate_limiting.dos011_recursive_operation_limit import (
    RecursiveOperationLimitCheck,
)
from medusa.checks.rate_limiting.dos012_batch_operation_limit import BatchOperationLimitCheck
from medusa.checks.rate_limiting.dos013_slowloris_risk import SlowlorisRiskCheck
from medusa.checks.rate_limiting.dos014_amplification_risk import AmplificationRiskCheck
from medusa.checks.rate_limiting.dos015_backpressure_missing import BackpressureMissingCheck
from medusa.core.models import Status
from tests.conftest import make_snapshot


class TestMissingRateLimitingCheck:
    """Tests for MissingRateLimitingCheck."""

    @pytest.fixture()
    def check(self) -> MissingRateLimitingCheck:
        return MissingRateLimitingCheck()

    async def test_metadata_loads_correctly(self, check: MissingRateLimitingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos001"
        assert meta.category == "rate_limiting"

    async def test_returns_empty_no_tools(self, check: MissingRateLimitingCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_resource_intensive_tool_no_rate_limit(
        self, check: MissingRateLimitingCheck
    ) -> None:
        """Resource-intensive tool (run_query) with no rate-limit params should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "run_query",
                    "description": "Execute a database query.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "sql": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Resource-intensive tool without rate limit should FAIL"
        assert "run_query" in fail_findings[0].status_extended

    async def test_fails_on_export_tool_no_rate_limit(
        self, check: MissingRateLimitingCheck
    ) -> None:
        """Export tool with no rate-limit params should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "export_data",
                    "description": "Export records from storage.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Export tool without rate limit should FAIL"

    async def test_passes_with_limit_param(
        self, check: MissingRateLimitingCheck
    ) -> None:
        """Resource-intensive tool with 'limit' param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "run_query",
                    "description": "Execute a query.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "sql": {"type": "string"},
                            "limit": {"type": "integer"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with 'limit' param should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_with_max_results_param(
        self, check: MissingRateLimitingCheck
    ) -> None:
        """Resource-intensive tool with 'max_results' param should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "search_records",
                    "description": "Search for records in the database.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "max_results": {"type": "integer"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with 'max_results' param should PASS"

    async def test_passes_with_config_rate_limit(
        self, check: MissingRateLimitingCheck
    ) -> None:
        """Config-level rate_limit should satisfy the check."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "run_query",
                    "description": "Execute a database query.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"sql": {"type": "string"}},
                    },
                }
            ],
            config_raw={"command": "node", "rate_limit": {"max_requests": 100}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config rate_limit should satisfy the check"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_skips_non_intensive_tools(
        self, check: MissingRateLimitingCheck
    ) -> None:
        """Tool named 'get_weather' with no resource indicators should not FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "calculate_sum",
                    "description": "Add two numbers together.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "number"},
                            "b": {"type": "number"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Non-intensive tool should not trigger FAIL"

    async def test_per_tool_findings(
        self, check: MissingRateLimitingCheck
    ) -> None:
        """Two intensive tools without limit should each get a FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "run_query",
                    "description": "Execute a database query.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"sql": {"type": "string"}},
                    },
                },
                {
                    "name": "export_data",
                    "description": "Export records from storage.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                    },
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 2, "Each intensive tool should get its own FAIL"
        failed_names = {f.resource_name for f in fail_findings}
        assert "run_query" in failed_names
        assert "export_data" in failed_names


class TestMissingRequestThrottlingCheck:
    """Tests for MissingRequestThrottlingCheck."""

    @pytest.fixture()
    def check(self) -> MissingRequestThrottlingCheck:
        return MissingRequestThrottlingCheck()

    async def test_metadata_loads_correctly(self, check: MissingRequestThrottlingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos002"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: MissingRequestThrottlingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestResourceExhaustionRiskCheck:
    """Tests for ResourceExhaustionRiskCheck."""

    @pytest.fixture()
    def check(self) -> ResourceExhaustionRiskCheck:
        return ResourceExhaustionRiskCheck()

    async def test_metadata_loads_correctly(self, check: ResourceExhaustionRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos003"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: ResourceExhaustionRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestConcurrentRequestLimitCheck:
    """Tests for ConcurrentRequestLimitCheck."""

    @pytest.fixture()
    def check(self) -> ConcurrentRequestLimitCheck:
        return ConcurrentRequestLimitCheck()

    async def test_metadata_loads_correctly(self, check: ConcurrentRequestLimitCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos004"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: ConcurrentRequestLimitCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPayloadSizeLimitCheck:
    """Tests for PayloadSizeLimitCheck."""

    @pytest.fixture()
    def check(self) -> PayloadSizeLimitCheck:
        return PayloadSizeLimitCheck()

    async def test_metadata_loads_correctly(self, check: PayloadSizeLimitCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos005"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: PayloadSizeLimitCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestTimeoutConfigurationCheck:
    """Tests for TimeoutConfigurationCheck."""

    @pytest.fixture()
    def check(self) -> TimeoutConfigurationCheck:
        return TimeoutConfigurationCheck()

    async def test_metadata_loads_correctly(self, check: TimeoutConfigurationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos006"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: TimeoutConfigurationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestConnectionPoolExhaustionCheck:
    """Tests for ConnectionPoolExhaustionCheck."""

    @pytest.fixture()
    def check(self) -> ConnectionPoolExhaustionCheck:
        return ConnectionPoolExhaustionCheck()

    async def test_metadata_loads_correctly(self, check: ConnectionPoolExhaustionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos007"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: ConnectionPoolExhaustionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMemoryExhaustionRiskCheck:
    """Tests for MemoryExhaustionRiskCheck."""

    @pytest.fixture()
    def check(self) -> MemoryExhaustionRiskCheck:
        return MemoryExhaustionRiskCheck()

    async def test_metadata_loads_correctly(self, check: MemoryExhaustionRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos008"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: MemoryExhaustionRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestDiskExhaustionRiskCheck:
    """Tests for DiskExhaustionRiskCheck."""

    @pytest.fixture()
    def check(self) -> DiskExhaustionRiskCheck:
        return DiskExhaustionRiskCheck()

    async def test_metadata_loads_correctly(self, check: DiskExhaustionRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos009"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: DiskExhaustionRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestCpuExhaustionRiskCheck:
    """Tests for CpuExhaustionRiskCheck."""

    @pytest.fixture()
    def check(self) -> CpuExhaustionRiskCheck:
        return CpuExhaustionRiskCheck()

    async def test_metadata_loads_correctly(self, check: CpuExhaustionRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos010"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: CpuExhaustionRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestRecursiveOperationLimitCheck:
    """Tests for RecursiveOperationLimitCheck."""

    @pytest.fixture()
    def check(self) -> RecursiveOperationLimitCheck:
        return RecursiveOperationLimitCheck()

    async def test_metadata_loads_correctly(self, check: RecursiveOperationLimitCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos011"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: RecursiveOperationLimitCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestBatchOperationLimitCheck:
    """Tests for BatchOperationLimitCheck."""

    @pytest.fixture()
    def check(self) -> BatchOperationLimitCheck:
        return BatchOperationLimitCheck()

    async def test_metadata_loads_correctly(self, check: BatchOperationLimitCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos012"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: BatchOperationLimitCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSlowlorisRiskCheck:
    """Tests for SlowlorisRiskCheck."""

    @pytest.fixture()
    def check(self) -> SlowlorisRiskCheck:
        return SlowlorisRiskCheck()

    async def test_metadata_loads_correctly(self, check: SlowlorisRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos013"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: SlowlorisRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestAmplificationRiskCheck:
    """Tests for AmplificationRiskCheck."""

    @pytest.fixture()
    def check(self) -> AmplificationRiskCheck:
        return AmplificationRiskCheck()

    async def test_metadata_loads_correctly(self, check: AmplificationRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos014"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: AmplificationRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestBackpressureMissingCheck:
    """Tests for BackpressureMissingCheck."""

    @pytest.fixture()
    def check(self) -> BackpressureMissingCheck:
        return BackpressureMissingCheck()

    async def test_metadata_loads_correctly(self, check: BackpressureMissingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "dos015"
        assert meta.category == "rate_limiting"

    async def test_stub_returns_empty(self, check: BackpressureMissingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
