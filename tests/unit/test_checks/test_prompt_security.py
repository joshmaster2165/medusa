"""Unit tests for Prompt Security checks (auto-generated stubs)."""

from __future__ import annotations

import pytest

from medusa.checks.prompt_security.pmt001_prompt_argument_injection import (
    PromptArgumentInjectionCheck,
)
from medusa.checks.prompt_security.pmt002_jailbreak_phrases_in_prompts import (
    JailbreakPhrasesInPromptsCheck,
)
from medusa.checks.prompt_security.pmt003_role_reassignment_in_prompts import (
    RoleReassignmentInPromptsCheck,
)
from medusa.checks.prompt_security.pmt004_prompt_template_injection import (
    PromptTemplateInjectionCheck,
)
from medusa.checks.prompt_security.pmt005_missing_prompt_sanitization import (
    MissingPromptSanitizationCheck,
)
from medusa.checks.prompt_security.pmt006_prompt_chaining_risk import PromptChainingRiskCheck
from medusa.checks.prompt_security.pmt007_excessive_prompt_arguments import (
    ExcessivePromptArgumentsCheck,
)
from medusa.checks.prompt_security.pmt008_prompt_argument_type_coercion import (
    PromptArgumentTypeCoercionCheck,
)
from medusa.checks.prompt_security.pmt009_default_prompt_arguments import (
    DefaultPromptArgumentsCheck,
)
from medusa.checks.prompt_security.pmt010_prompt_output_manipulation import (
    PromptOutputManipulationCheck,
)
from medusa.checks.prompt_security.pmt011_multilingual_prompt_injection import (
    MultilingualPromptInjectionCheck,
)
from medusa.checks.prompt_security.pmt012_prompt_encoding_bypass import PromptEncodingBypassCheck
from medusa.checks.prompt_security.pmt013_prompt_length_limit import PromptLengthLimitCheck
from medusa.checks.prompt_security.pmt014_prompt_history_manipulation import (
    PromptHistoryManipulationCheck,
)
from medusa.checks.prompt_security.pmt015_prompt_metadata_leakage import PromptMetadataLeakageCheck
from tests.conftest import make_snapshot


class TestPromptArgumentInjectionCheck:
    """Tests for PromptArgumentInjectionCheck."""

    @pytest.fixture()
    def check(self) -> PromptArgumentInjectionCheck:
        return PromptArgumentInjectionCheck()

    async def test_metadata_loads_correctly(self, check: PromptArgumentInjectionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt001"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: PromptArgumentInjectionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestJailbreakPhrasesInPromptsCheck:
    """Tests for JailbreakPhrasesInPromptsCheck."""

    @pytest.fixture()
    def check(self) -> JailbreakPhrasesInPromptsCheck:
        return JailbreakPhrasesInPromptsCheck()

    async def test_metadata_loads_correctly(self, check: JailbreakPhrasesInPromptsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt002"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: JailbreakPhrasesInPromptsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestRoleReassignmentInPromptsCheck:
    """Tests for RoleReassignmentInPromptsCheck."""

    @pytest.fixture()
    def check(self) -> RoleReassignmentInPromptsCheck:
        return RoleReassignmentInPromptsCheck()

    async def test_metadata_loads_correctly(self, check: RoleReassignmentInPromptsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt003"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: RoleReassignmentInPromptsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPromptTemplateInjectionCheck:
    """Tests for PromptTemplateInjectionCheck."""

    @pytest.fixture()
    def check(self) -> PromptTemplateInjectionCheck:
        return PromptTemplateInjectionCheck()

    async def test_metadata_loads_correctly(self, check: PromptTemplateInjectionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt004"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: PromptTemplateInjectionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingPromptSanitizationCheck:
    """Tests for MissingPromptSanitizationCheck."""

    @pytest.fixture()
    def check(self) -> MissingPromptSanitizationCheck:
        return MissingPromptSanitizationCheck()

    async def test_metadata_loads_correctly(self, check: MissingPromptSanitizationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt005"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: MissingPromptSanitizationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPromptChainingRiskCheck:
    """Tests for PromptChainingRiskCheck."""

    @pytest.fixture()
    def check(self) -> PromptChainingRiskCheck:
        return PromptChainingRiskCheck()

    async def test_metadata_loads_correctly(self, check: PromptChainingRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt006"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: PromptChainingRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestExcessivePromptArgumentsCheck:
    """Tests for ExcessivePromptArgumentsCheck."""

    @pytest.fixture()
    def check(self) -> ExcessivePromptArgumentsCheck:
        return ExcessivePromptArgumentsCheck()

    async def test_metadata_loads_correctly(self, check: ExcessivePromptArgumentsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt007"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: ExcessivePromptArgumentsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPromptArgumentTypeCoercionCheck:
    """Tests for PromptArgumentTypeCoercionCheck."""

    @pytest.fixture()
    def check(self) -> PromptArgumentTypeCoercionCheck:
        return PromptArgumentTypeCoercionCheck()

    async def test_metadata_loads_correctly(self, check: PromptArgumentTypeCoercionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt008"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: PromptArgumentTypeCoercionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestDefaultPromptArgumentsCheck:
    """Tests for DefaultPromptArgumentsCheck."""

    @pytest.fixture()
    def check(self) -> DefaultPromptArgumentsCheck:
        return DefaultPromptArgumentsCheck()

    async def test_metadata_loads_correctly(self, check: DefaultPromptArgumentsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt009"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: DefaultPromptArgumentsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPromptOutputManipulationCheck:
    """Tests for PromptOutputManipulationCheck."""

    @pytest.fixture()
    def check(self) -> PromptOutputManipulationCheck:
        return PromptOutputManipulationCheck()

    async def test_metadata_loads_correctly(self, check: PromptOutputManipulationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt010"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: PromptOutputManipulationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMultilingualPromptInjectionCheck:
    """Tests for MultilingualPromptInjectionCheck."""

    @pytest.fixture()
    def check(self) -> MultilingualPromptInjectionCheck:
        return MultilingualPromptInjectionCheck()

    async def test_metadata_loads_correctly(self, check: MultilingualPromptInjectionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt011"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: MultilingualPromptInjectionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPromptEncodingBypassCheck:
    """Tests for PromptEncodingBypassCheck."""

    @pytest.fixture()
    def check(self) -> PromptEncodingBypassCheck:
        return PromptEncodingBypassCheck()

    async def test_metadata_loads_correctly(self, check: PromptEncodingBypassCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt012"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: PromptEncodingBypassCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPromptLengthLimitCheck:
    """Tests for PromptLengthLimitCheck."""

    @pytest.fixture()
    def check(self) -> PromptLengthLimitCheck:
        return PromptLengthLimitCheck()

    async def test_metadata_loads_correctly(self, check: PromptLengthLimitCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt013"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: PromptLengthLimitCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPromptHistoryManipulationCheck:
    """Tests for PromptHistoryManipulationCheck."""

    @pytest.fixture()
    def check(self) -> PromptHistoryManipulationCheck:
        return PromptHistoryManipulationCheck()

    async def test_metadata_loads_correctly(self, check: PromptHistoryManipulationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt014"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: PromptHistoryManipulationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPromptMetadataLeakageCheck:
    """Tests for PromptMetadataLeakageCheck."""

    @pytest.fixture()
    def check(self) -> PromptMetadataLeakageCheck:
        return PromptMetadataLeakageCheck()

    async def test_metadata_loads_correctly(self, check: PromptMetadataLeakageCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "pmt015"
        assert meta.category == "prompt_security"

    async def test_stub_returns_empty(self, check: PromptMetadataLeakageCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
