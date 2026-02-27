"""Unit tests for Sampling Security checks (auto-generated stubs)."""

from __future__ import annotations

import pytest

from medusa.checks.sampling_security.samp001_sampling_injection import SamplingInjectionCheck
from medusa.checks.sampling_security.samp002_model_manipulation_via_sampling import (
    ModelManipulationViaSamplingCheck,
)
from medusa.checks.sampling_security.samp003_unauthorized_sampling import UnauthorizedSamplingCheck
from medusa.checks.sampling_security.samp004_sampling_data_exfiltration import (
    SamplingDataExfiltrationCheck,
)
from medusa.checks.sampling_security.samp005_sampling_privilege_escalation import (
    SamplingPrivilegeEscalationCheck,
)
from medusa.checks.sampling_security.samp006_recursive_sampling import RecursiveSamplingCheck
from medusa.checks.sampling_security.samp007_sampling_without_rate_limit import (
    SamplingWithoutRateLimitCheck,
)
from medusa.checks.sampling_security.samp008_sampling_context_manipulation import (
    SamplingContextManipulationCheck,
)
from medusa.checks.sampling_security.samp009_sampling_response_validation import (
    SamplingResponseValidationCheck,
)
from medusa.checks.sampling_security.samp010_cross_server_sampling import CrossServerSamplingCheck
from medusa.checks.sampling_security.samp011_sampling_token_exhaustion import (
    SamplingTokenExhaustionCheck,
)
from medusa.checks.sampling_security.samp012_sampling_output_injection import (
    SamplingOutputInjectionCheck,
)
from medusa.checks.sampling_security.samp013_model_selection_manipulation import (
    ModelSelectionManipulationCheck,
)
from medusa.checks.sampling_security.samp014_sampling_history_poisoning import (
    SamplingHistoryPoisoningCheck,
)
from medusa.checks.sampling_security.samp015_sampling_system_prompt_override import (
    SamplingSystemPromptOverrideCheck,
)
from tests.conftest import make_snapshot


class TestSamplingInjectionCheck:
    """Tests for SamplingInjectionCheck."""

    @pytest.fixture()
    def check(self) -> SamplingInjectionCheck:
        return SamplingInjectionCheck()

    async def test_metadata_loads_correctly(self, check: SamplingInjectionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp001"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: SamplingInjectionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestModelManipulationViaSamplingCheck:
    """Tests for ModelManipulationViaSamplingCheck."""

    @pytest.fixture()
    def check(self) -> ModelManipulationViaSamplingCheck:
        return ModelManipulationViaSamplingCheck()

    async def test_metadata_loads_correctly(self, check: ModelManipulationViaSamplingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp002"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: ModelManipulationViaSamplingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestUnauthorizedSamplingCheck:
    """Tests for UnauthorizedSamplingCheck."""

    @pytest.fixture()
    def check(self) -> UnauthorizedSamplingCheck:
        return UnauthorizedSamplingCheck()

    async def test_metadata_loads_correctly(self, check: UnauthorizedSamplingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp003"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: UnauthorizedSamplingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSamplingDataExfiltrationCheck:
    """Tests for SamplingDataExfiltrationCheck."""

    @pytest.fixture()
    def check(self) -> SamplingDataExfiltrationCheck:
        return SamplingDataExfiltrationCheck()

    async def test_metadata_loads_correctly(self, check: SamplingDataExfiltrationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp004"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: SamplingDataExfiltrationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSamplingPrivilegeEscalationCheck:
    """Tests for SamplingPrivilegeEscalationCheck."""

    @pytest.fixture()
    def check(self) -> SamplingPrivilegeEscalationCheck:
        return SamplingPrivilegeEscalationCheck()

    async def test_metadata_loads_correctly(self, check: SamplingPrivilegeEscalationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp005"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: SamplingPrivilegeEscalationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestRecursiveSamplingCheck:
    """Tests for RecursiveSamplingCheck."""

    @pytest.fixture()
    def check(self) -> RecursiveSamplingCheck:
        return RecursiveSamplingCheck()

    async def test_metadata_loads_correctly(self, check: RecursiveSamplingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp006"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: RecursiveSamplingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSamplingWithoutRateLimitCheck:
    """Tests for SamplingWithoutRateLimitCheck."""

    @pytest.fixture()
    def check(self) -> SamplingWithoutRateLimitCheck:
        return SamplingWithoutRateLimitCheck()

    async def test_metadata_loads_correctly(self, check: SamplingWithoutRateLimitCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp007"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: SamplingWithoutRateLimitCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSamplingContextManipulationCheck:
    """Tests for SamplingContextManipulationCheck."""

    @pytest.fixture()
    def check(self) -> SamplingContextManipulationCheck:
        return SamplingContextManipulationCheck()

    async def test_metadata_loads_correctly(self, check: SamplingContextManipulationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp008"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: SamplingContextManipulationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSamplingResponseValidationCheck:
    """Tests for SamplingResponseValidationCheck."""

    @pytest.fixture()
    def check(self) -> SamplingResponseValidationCheck:
        return SamplingResponseValidationCheck()

    async def test_metadata_loads_correctly(self, check: SamplingResponseValidationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp009"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: SamplingResponseValidationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestCrossServerSamplingCheck:
    """Tests for CrossServerSamplingCheck."""

    @pytest.fixture()
    def check(self) -> CrossServerSamplingCheck:
        return CrossServerSamplingCheck()

    async def test_metadata_loads_correctly(self, check: CrossServerSamplingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp010"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: CrossServerSamplingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSamplingTokenExhaustionCheck:
    """Tests for SamplingTokenExhaustionCheck."""

    @pytest.fixture()
    def check(self) -> SamplingTokenExhaustionCheck:
        return SamplingTokenExhaustionCheck()

    async def test_metadata_loads_correctly(self, check: SamplingTokenExhaustionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp011"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: SamplingTokenExhaustionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSamplingOutputInjectionCheck:
    """Tests for SamplingOutputInjectionCheck."""

    @pytest.fixture()
    def check(self) -> SamplingOutputInjectionCheck:
        return SamplingOutputInjectionCheck()

    async def test_metadata_loads_correctly(self, check: SamplingOutputInjectionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp012"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: SamplingOutputInjectionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestModelSelectionManipulationCheck:
    """Tests for ModelSelectionManipulationCheck."""

    @pytest.fixture()
    def check(self) -> ModelSelectionManipulationCheck:
        return ModelSelectionManipulationCheck()

    async def test_metadata_loads_correctly(self, check: ModelSelectionManipulationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp013"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: ModelSelectionManipulationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSamplingHistoryPoisoningCheck:
    """Tests for SamplingHistoryPoisoningCheck."""

    @pytest.fixture()
    def check(self) -> SamplingHistoryPoisoningCheck:
        return SamplingHistoryPoisoningCheck()

    async def test_metadata_loads_correctly(self, check: SamplingHistoryPoisoningCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp014"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: SamplingHistoryPoisoningCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSamplingSystemPromptOverrideCheck:
    """Tests for SamplingSystemPromptOverrideCheck."""

    @pytest.fixture()
    def check(self) -> SamplingSystemPromptOverrideCheck:
        return SamplingSystemPromptOverrideCheck()

    async def test_metadata_loads_correctly(self, check: SamplingSystemPromptOverrideCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "samp015"
        assert meta.category == "sampling_security"

    async def test_stub_returns_empty(self, check: SamplingSystemPromptOverrideCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
