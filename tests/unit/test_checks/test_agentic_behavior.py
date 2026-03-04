"""Unit tests for Agentic Behavior checks (agent001-agent025)."""

from __future__ import annotations

import pytest

from medusa.checks.agentic_behavior.agent001_missing_human_in_loop import MissingHumanInLoopCheck
from medusa.checks.agentic_behavior.agent002_autonomous_action_risk import AutonomousActionRiskCheck
from medusa.checks.agentic_behavior.agent003_agent_loop_detection import AgentLoopDetectionCheck
from medusa.checks.agentic_behavior.agent004_multi_step_attack_chain import (
    MultiStepAttackChainCheck,
)
from medusa.checks.agentic_behavior.agent005_delegation_without_auth import (
    DelegationWithoutAuthCheck,
)
from medusa.checks.agentic_behavior.agent006_tool_selection_manipulation import (
    ToolSelectionManipulationCheck,
)
from medusa.checks.agentic_behavior.agent007_agent_memory_poisoning import AgentMemoryPoisoningCheck
from medusa.checks.agentic_behavior.agent008_goal_hijacking import GoalHijackingCheck
from medusa.checks.agentic_behavior.agent009_reward_hacking import RewardHackingCheck
from medusa.checks.agentic_behavior.agent010_agent_impersonation import AgentImpersonationCheck
from medusa.checks.agentic_behavior.agent011_unbounded_tool_calls import UnboundedToolCallsCheck
from medusa.checks.agentic_behavior.agent012_agent_persistence_risk import AgentPersistenceRiskCheck
from medusa.checks.agentic_behavior.agent013_capability_accumulation import (
    CapabilityAccumulationCheck,
)
from medusa.checks.agentic_behavior.agent014_indirect_prompt_injection import (
    IndirectPromptInjectionCheck,
)
from medusa.checks.agentic_behavior.agent015_agent_data_hoarding import AgentDataHoardingCheck
from medusa.checks.agentic_behavior.agent016_unauthorized_external_comms import (
    UnauthorizedExternalCommsCheck,
)
from medusa.checks.agentic_behavior.agent017_agent_self_modification import (
    AgentSelfModificationCheck,
)
from medusa.checks.agentic_behavior.agent018_multi_agent_coordination_risk import (
    MultiAgentCoordinationRiskCheck,
)
from medusa.checks.agentic_behavior.agent019_agent_resource_exhaustion import (
    AgentResourceExhaustionCheck,
)
from medusa.checks.agentic_behavior.agent020_missing_agent_audit_trail import (
    MissingAgentAuditTrailCheck,
)
from medusa.checks.agentic_behavior.agent021_excessive_tool_count import (
    ExcessiveToolCountCheck,
)
from medusa.checks.agentic_behavior.agent022_missing_tool_annotations import (
    MissingToolAnnotationsCheck,
)
from medusa.checks.agentic_behavior.agent023_conflicting_tool_names import (
    ConflictingToolNamesCheck,
)
from medusa.checks.agentic_behavior.agent024_unrestricted_tool_output import (
    UnrestrictedToolOutputCheck,
)
from medusa.checks.agentic_behavior.agent025_missing_sampling import (
    MissingSamplingCheck,
)
from medusa.core.models import Status
from tests.conftest import make_snapshot


class TestMissingHumanInLoopCheck:
    """Tests for MissingHumanInLoopCheck."""

    @pytest.fixture()
    def check(self) -> MissingHumanInLoopCheck:
        return MissingHumanInLoopCheck()

    async def test_metadata_loads_correctly(self, check: MissingHumanInLoopCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent001"
        assert meta.category == "agentic_behavior"

    async def test_returns_empty_no_tools(self, check: MissingHumanInLoopCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_destructive_tool_no_confirmation(
        self, check: MissingHumanInLoopCheck
    ) -> None:
        """Destructive tool without confirmation should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Permanently removes a user account.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Destructive tool should be flagged"
        assert "delete_user" in fail_findings[0].status_extended

    async def test_fails_on_privileged_tool_no_confirmation(
        self, check: MissingHumanInLoopCheck
    ) -> None:
        """Privileged tool without confirmation should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "run_command",
                    "description": "Execute a shell command on the server.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Privileged tool should be flagged"

    async def test_passes_on_read_only_tools(self, check: MissingHumanInLoopCheck) -> None:
        """Read-only tools should PASS even without confirmation."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Fetch weather data for a city.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "search_users",
                    "description": "Search for users by name.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1, "Read-only tools should not require confirmation"

    async def test_passes_with_confirmation_config(self, check: MissingHumanInLoopCheck) -> None:
        """Destructive tool with confirmation config should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Permanently removes a user account.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
            config_raw={"command": "node", "confirmation": True},
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1, "Confirmation config should satisfy the check"

    async def test_passes_with_confirm_schema_param(self, check: MissingHumanInLoopCheck) -> None:
        """Destructive tool with 'confirm' property in schema should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Permanently removes a user account.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "user_id": {"type": "string"},
                            "confirm": {"type": "boolean", "description": "Set to true to confirm deletion"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with 'confirm' param should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_with_dry_run_schema_param(self, check: MissingHumanInLoopCheck) -> None:
        """Destructive tool with 'dry_run' property in schema should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "drop_table",
                    "description": "Drops a database table permanently.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "table": {"type": "string"},
                            "dry_run": {"type": "boolean", "description": "Preview changes without executing"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with 'dry_run' param should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_risk_classification_in_evidence(self, check: MissingHumanInLoopCheck) -> None:
        """Evidence should include risk classification labels."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Remove a user.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
            config_raw={"command": "node"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "destructive" in fail_findings[0].evidence.lower()


# ==========================================================================
# AGENT-002: Autonomous Action Risk
# ==========================================================================


class TestAutonomousActionRiskCheck:
    """Tests for AutonomousActionRiskCheck."""

    @pytest.fixture()
    def check(self) -> AutonomousActionRiskCheck:
        return AutonomousActionRiskCheck()

    async def test_metadata_loads_correctly(self, check: AutonomousActionRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent002"
        assert meta.category == "agentic_behavior"

    async def test_returns_empty_no_tools(self, check: AutonomousActionRiskCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_destructive_tool_no_safeguards(
        self, check: AutonomousActionRiskCheck
    ) -> None:
        """Destructive tool (delete_user) with no confirm/rate_limit params should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Permanently deletes a user account.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "user_id": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Destructive tool without safeguards should FAIL"
        assert "delete_user" in fail_findings[0].status_extended

    async def test_fails_on_exfiltrative_tool_no_safeguards(
        self, check: AutonomousActionRiskCheck
    ) -> None:
        """Exfiltrative tool (export_data with callback_url) with no safeguards should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "export_data",
                    "description": "Export all user data and send it externally.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "callback_url": {"type": "string", "description": "URL to send results"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Exfiltrative tool without safeguards should FAIL"

    async def test_passes_with_confirmation_param(
        self, check: AutonomousActionRiskCheck
    ) -> None:
        """Destructive tool with 'confirm' property in schema should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Permanently deletes a user account.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "user_id": {"type": "string"},
                            "confirm": {"type": "boolean"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with 'confirm' param should not FAIL"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_with_rate_limit_param(
        self, check: AutonomousActionRiskCheck
    ) -> None:
        """Tool with 'rate_limit' property in schema should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Permanently deletes a user account.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "user_id": {"type": "string"},
                            "rate_limit": {"type": "integer"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Tool with 'rate_limit' param should not FAIL"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_on_read_only_tools(
        self, check: AutonomousActionRiskCheck
    ) -> None:
        """Read-only tool (get_weather) should PASS without safeguards."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Fetch current weather data for a city.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1, "Read-only tool should PASS"
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_per_tool_findings(
        self, check: AutonomousActionRiskCheck
    ) -> None:
        """Two destructive tools without safeguards should each get their own FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Permanently deletes a user account.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "drop_database",
                    "description": "Drops the entire database.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 2, "Each destructive tool should get its own FAIL"
        failed_names = {f.resource_name for f in fail_findings}
        assert "delete_user" in failed_names
        assert "drop_database" in failed_names


# ==========================================================================
# AGENT-003: Agent Loop Detection
# ==========================================================================


class TestAgentLoopDetectionCheck:
    """Tests for AgentLoopDetectionCheck."""

    @pytest.fixture()
    def check(self) -> AgentLoopDetectionCheck:
        return AgentLoopDetectionCheck()

    async def test_metadata_loads_correctly(self, check: AgentLoopDetectionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent003"
        assert meta.category == "agentic_behavior"

    async def test_returns_empty_no_tools(self, check: AgentLoopDetectionCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_unconstrained_depth(self, check: AgentLoopDetectionCheck) -> None:
        """Tool with 'depth' param and no maximum constraint should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "crawl_site",
                    "description": "Crawl a website recursively.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "depth": {"type": "integer", "description": "Crawl depth"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Unconstrained depth param should FAIL"
        assert "depth" in fail_findings[0].status_extended.lower()

    async def test_passes_on_constrained_depth(self, check: AgentLoopDetectionCheck) -> None:
        """Tool with 'depth' param plus maximum:10 should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "crawl_site",
                    "description": "Crawl a website recursively.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "depth": {"type": "integer", "maximum": 10},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Constrained depth param should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_fails_on_unconstrained_max_iterations(
        self, check: AgentLoopDetectionCheck
    ) -> None:
        """Tool with 'max_iterations' param but no maximum/enum constraint should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "retry_task",
                    "description": "Retry a task multiple times.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task_id": {"type": "string"},
                            "max_iterations": {"type": "integer"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Unconstrained max_iterations should FAIL"

    async def test_passes_with_enum_constraint(self, check: AgentLoopDetectionCheck) -> None:
        """Tool with 'level' param constrained by enum should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "scan_directory",
                    "description": "Scan a directory tree.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "level": {"type": "string", "enum": ["shallow", "medium", "deep"]},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Enum-constrained param should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_fails_on_circular_reference(self, check: AgentLoopDetectionCheck) -> None:
        """Tool whose description mentions another tool by name should FAIL for circular ref."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "tool_a",
                    "description": "Processes data and then calls tool_b for finalization.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "tool_b",
                    "description": "Finalizes data processing.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Circular reference risk should FAIL"
        # Check that tool_b is mentioned as referenced
        assert any("tool_b" in f.status_extended for f in fail_findings)

    async def test_passes_no_recursion_params(self, check: AgentLoopDetectionCheck) -> None:
        """Simple tools with no recursion params should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Get current weather for a city.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                    },
                },
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
                },
            ],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_config_safety_mitigates(self, check: AgentLoopDetectionCheck) -> None:
        """Unconstrained depth with config max_iterations should produce no FAIL finding."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "crawl_site",
                    "description": "Crawl a website recursively.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "depth": {"type": "integer"},
                        },
                    },
                }
            ],
            config_raw={"command": "node", "max_iterations": 100},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        # Config safety key should mitigate unconstrained recursion params
        # (circular reference findings are separate and always emitted)
        unconstrained_fails = [
            f for f in fail_findings if "unconstrained" in f.status_extended.lower()
            or "without constraints" in f.status_extended.lower()
        ]
        assert len(unconstrained_fails) == 0, (
            "Config max_iterations should mitigate unconstrained recursion params"
        )


# ==========================================================================
# AGENT-004: Multi-Step Attack Chain
# ==========================================================================


class TestMultiStepAttackChainCheck:
    """Tests for MultiStepAttackChainCheck."""

    @pytest.fixture()
    def check(self) -> MultiStepAttackChainCheck:
        return MultiStepAttackChainCheck()

    async def test_metadata_loads_correctly(self, check: MultiStepAttackChainCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent004"
        assert meta.category == "agentic_behavior"

    async def test_returns_empty_no_tools(self, check: MultiStepAttackChainCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_data_theft_chain(self, check: MultiStepAttackChainCheck) -> None:
        """READ_ONLY + EXFILTRATIVE tools should FAIL with 'data theft chain'."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_user",
                    "description": "Retrieve user data from the database.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "send_webhook",
                    "description": "Send data to an external webhook endpoint.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"url": {"type": "string"}, "data": {"type": "string"}},
                    },
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Data theft chain should be detected"
        assert any("data theft" in f.status_extended.lower() for f in fail_findings)

    async def test_fails_on_informed_destruction(self, check: MultiStepAttackChainCheck) -> None:
        """READ_ONLY + DESTRUCTIVE tools should FAIL with 'informed destruction'."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_user",
                    "description": "Retrieve user data from the database.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "delete_user",
                    "description": "Permanently deletes a user account.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Informed destruction chain should be detected"
        assert any("informed destruction" in f.status_extended.lower() for f in fail_findings)

    async def test_fails_on_privilege_exfil_chain(self, check: MultiStepAttackChainCheck) -> None:
        """PRIVILEGED + EXFILTRATIVE tools should FAIL with 'privilege-to-exfil'."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "run_command",
                    "description": "Execute a shell command on the server.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "send_webhook",
                    "description": "Send data to an external webhook endpoint.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"url": {"type": "string"}},
                    },
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Privilege-to-exfil chain should be detected"
        assert any("privilege" in f.status_extended.lower() for f in fail_findings)

    async def test_passes_on_safe_tool_combo(self, check: MultiStepAttackChainCheck) -> None:
        """READ_ONLY tools only should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Fetch current weather data.",
                    "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1, "Safe tool combo should PASS"
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0

    async def test_config_chain_limit_mitigates(self, check: MultiStepAttackChainCheck) -> None:
        """Dangerous combo with config 'max_tool_calls' should produce no FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_user",
                    "description": "Retrieve user data.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "send_webhook",
                    "description": "Send data to a webhook.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
            config_raw={"command": "node", "max_tool_calls": 5},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config chain limit should mitigate dangerous chains"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_multiple_chains_detected(self, check: MultiStepAttackChainCheck) -> None:
        """Tools that trigger both data_theft and informed_destruction chains."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_user",
                    "description": "Retrieve user data from the database.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "send_webhook",
                    "description": "Send data to an external webhook.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "delete_user",
                    "description": "Permanently deletes a user account.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 2, "Multiple chain types should be detected"
        chain_labels = [f.status_extended.lower() for f in fail_findings]
        assert any("data theft" in label for label in chain_labels)
        assert any("informed destruction" in label for label in chain_labels)


# ==========================================================================
# AGENT-005: Delegation Without Authorization
# ==========================================================================


class TestDelegationWithoutAuthCheck:
    """Tests for DelegationWithoutAuthCheck."""

    @pytest.fixture()
    def check(self) -> DelegationWithoutAuthCheck:
        return DelegationWithoutAuthCheck()

    async def test_metadata_loads_correctly(self, check: DelegationWithoutAuthCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent005"
        assert meta.category == "agentic_behavior"

    async def test_returns_empty_no_tools(self, check: DelegationWithoutAuthCheck) -> None:
        """Empty tools list should return no findings."""
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_fails_on_delegation_tool_no_auth(
        self, check: DelegationWithoutAuthCheck
    ) -> None:
        """Tool named 'delegate_task' with no auth params should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delegate_task",
                    "description": "Forward a task to another agent for processing.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task": {"type": "string"},
                            "agent_name": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Delegation tool without auth should FAIL"
        assert "delegate_task" in fail_findings[0].status_extended

    async def test_fails_on_proxy_tool_no_auth(
        self, check: DelegationWithoutAuthCheck
    ) -> None:
        """Tool with 'proxy' in description and no auth should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "forward_request",
                    "description": "Proxy the request to another service for handling.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "payload": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1, "Proxy tool without auth should FAIL"

    async def test_passes_with_auth_param(self, check: DelegationWithoutAuthCheck) -> None:
        """Delegation tool with 'token' property should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delegate_task",
                    "description": "Forward a task to another agent.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task": {"type": "string"},
                            "token": {"type": "string", "description": "Auth token"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Delegation tool with 'token' should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_with_api_key_param(self, check: DelegationWithoutAuthCheck) -> None:
        """Delegation tool with 'api_key' property should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delegate_task",
                    "description": "Forward a task to another agent.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task": {"type": "string"},
                            "api_key": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Delegation tool with 'api_key' should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_with_config_auth(self, check: DelegationWithoutAuthCheck) -> None:
        """Delegation tool with no schema auth but config has auth keys should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delegate_task",
                    "description": "Forward a task to another agent.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"task": {"type": "string"}},
                    },
                }
            ],
            config_raw={"command": "node", "auth": {"type": "bearer", "token": "abc123"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "Config auth should satisfy the check"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_skips_non_delegation_tools(self, check: DelegationWithoutAuthCheck) -> None:
        """Non-delegation tool (get_weather) should produce no delegation FAIL findings."""
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
        assert len(fail_findings) == 0, "Non-delegation tools should not trigger delegation FAIL"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_all_delegation_tools_have_auth(
        self, check: DelegationWithoutAuthCheck
    ) -> None:
        """Multiple delegation tools, all with auth params, should result in PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delegate_task",
                    "description": "Forward a task to another agent.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task": {"type": "string"},
                            "token": {"type": "string"},
                        },
                    },
                },
                {
                    "name": "proxy_request",
                    "description": "Relay a request to a proxy service.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "api_key": {"type": "string"},
                        },
                    },
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0, "All delegation tools with auth should PASS"
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# AGENT-006: Tool Selection Manipulation
# ==========================================================================


class TestToolSelectionManipulationCheck:
    """Tests for ToolSelectionManipulationCheck."""

    @pytest.fixture()
    def check(self) -> ToolSelectionManipulationCheck:
        return ToolSelectionManipulationCheck()

    async def test_metadata_loads_correctly(self, check: ToolSelectionManipulationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent006"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: ToolSelectionManipulationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestAgentMemoryPoisoningCheck:
    """Tests for AgentMemoryPoisoningCheck."""

    @pytest.fixture()
    def check(self) -> AgentMemoryPoisoningCheck:
        return AgentMemoryPoisoningCheck()

    async def test_metadata_loads_correctly(self, check: AgentMemoryPoisoningCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent007"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: AgentMemoryPoisoningCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestGoalHijackingCheck:
    """Tests for GoalHijackingCheck."""

    @pytest.fixture()
    def check(self) -> GoalHijackingCheck:
        return GoalHijackingCheck()

    async def test_metadata_loads_correctly(self, check: GoalHijackingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent008"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: GoalHijackingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestRewardHackingCheck:
    """Tests for RewardHackingCheck."""

    @pytest.fixture()
    def check(self) -> RewardHackingCheck:
        return RewardHackingCheck()

    async def test_metadata_loads_correctly(self, check: RewardHackingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent009"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: RewardHackingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestAgentImpersonationCheck:
    """Tests for AgentImpersonationCheck."""

    @pytest.fixture()
    def check(self) -> AgentImpersonationCheck:
        return AgentImpersonationCheck()

    async def test_metadata_loads_correctly(self, check: AgentImpersonationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent010"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: AgentImpersonationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestUnboundedToolCallsCheck:
    """Tests for UnboundedToolCallsCheck."""

    @pytest.fixture()
    def check(self) -> UnboundedToolCallsCheck:
        return UnboundedToolCallsCheck()

    async def test_metadata_loads_correctly(self, check: UnboundedToolCallsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent011"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: UnboundedToolCallsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestAgentPersistenceRiskCheck:
    """Tests for AgentPersistenceRiskCheck."""

    @pytest.fixture()
    def check(self) -> AgentPersistenceRiskCheck:
        return AgentPersistenceRiskCheck()

    async def test_metadata_loads_correctly(self, check: AgentPersistenceRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent012"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: AgentPersistenceRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestCapabilityAccumulationCheck:
    """Tests for CapabilityAccumulationCheck."""

    @pytest.fixture()
    def check(self) -> CapabilityAccumulationCheck:
        return CapabilityAccumulationCheck()

    async def test_metadata_loads_correctly(self, check: CapabilityAccumulationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent013"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: CapabilityAccumulationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestIndirectPromptInjectionCheck:
    """Tests for IndirectPromptInjectionCheck."""

    @pytest.fixture()
    def check(self) -> IndirectPromptInjectionCheck:
        return IndirectPromptInjectionCheck()

    async def test_metadata_loads_correctly(self, check: IndirectPromptInjectionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent014"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: IndirectPromptInjectionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestAgentDataHoardingCheck:
    """Tests for AgentDataHoardingCheck."""

    @pytest.fixture()
    def check(self) -> AgentDataHoardingCheck:
        return AgentDataHoardingCheck()

    async def test_metadata_loads_correctly(self, check: AgentDataHoardingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent015"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: AgentDataHoardingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestUnauthorizedExternalCommsCheck:
    """Tests for UnauthorizedExternalCommsCheck."""

    @pytest.fixture()
    def check(self) -> UnauthorizedExternalCommsCheck:
        return UnauthorizedExternalCommsCheck()

    async def test_metadata_loads_correctly(self, check: UnauthorizedExternalCommsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent016"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: UnauthorizedExternalCommsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestAgentSelfModificationCheck:
    """Tests for AgentSelfModificationCheck."""

    @pytest.fixture()
    def check(self) -> AgentSelfModificationCheck:
        return AgentSelfModificationCheck()

    async def test_metadata_loads_correctly(self, check: AgentSelfModificationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent017"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: AgentSelfModificationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMultiAgentCoordinationRiskCheck:
    """Tests for MultiAgentCoordinationRiskCheck."""

    @pytest.fixture()
    def check(self) -> MultiAgentCoordinationRiskCheck:
        return MultiAgentCoordinationRiskCheck()

    async def test_metadata_loads_correctly(self, check: MultiAgentCoordinationRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent018"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: MultiAgentCoordinationRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestAgentResourceExhaustionCheck:
    """Tests for AgentResourceExhaustionCheck."""

    @pytest.fixture()
    def check(self) -> AgentResourceExhaustionCheck:
        return AgentResourceExhaustionCheck()

    async def test_metadata_loads_correctly(self, check: AgentResourceExhaustionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent019"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: AgentResourceExhaustionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingAgentAuditTrailCheck:
    """Tests for MissingAgentAuditTrailCheck."""

    @pytest.fixture()
    def check(self) -> MissingAgentAuditTrailCheck:
        return MissingAgentAuditTrailCheck()

    async def test_metadata_loads_correctly(self, check: MissingAgentAuditTrailCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent020"
        assert meta.category == "agentic_behavior"

    async def test_stub_returns_empty(self, check: MissingAgentAuditTrailCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


# ==========================================================================
# AGENT-021: Excessive Tool Count
# ==========================================================================


class TestExcessiveToolCountCheck:
    """Tests for ExcessiveToolCountCheck."""

    @pytest.fixture()
    def check(self) -> ExcessiveToolCountCheck:
        return ExcessiveToolCountCheck()

    async def test_metadata_loads_correctly(self, check: ExcessiveToolCountCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent021"
        assert meta.category == "agentic_behavior"

    async def test_fails_on_excessive_tool_count(self, check: ExcessiveToolCountCheck) -> None:
        """Server with 60 tools (above threshold of 50) should FAIL."""
        tools = [
            {
                "name": f"tool_{i}",
                "description": f"Tool number {i}.",
                "inputSchema": {"type": "object", "properties": {}},
            }
            for i in range(60)
        ]
        snapshot = make_snapshot(tools=tools)
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "60" in fail_findings[0].evidence

    async def test_passes_on_small_tool_count(self, check: ExcessiveToolCountCheck) -> None:
        """Server with 5 tools should PASS."""
        tools = [
            {
                "name": f"tool_{i}",
                "description": f"Tool number {i}.",
                "inputSchema": {"type": "object", "properties": {}},
            }
            for i in range(5)
        ]
        snapshot = make_snapshot(tools=tools)
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_not_applicable_when_no_tools(self, check: ExcessiveToolCountCheck) -> None:
        """No tools means no findings."""
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# AGENT-022: Missing Tool Annotations
# ==========================================================================


class TestMissingToolAnnotationsCheck:
    """Tests for MissingToolAnnotationsCheck."""

    @pytest.fixture()
    def check(self) -> MissingToolAnnotationsCheck:
        return MissingToolAnnotationsCheck()

    async def test_metadata_loads_correctly(self, check: MissingToolAnnotationsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent022"
        assert meta.category == "agentic_behavior"

    async def test_fails_on_tools_without_annotations(
        self, check: MissingToolAnnotationsCheck
    ) -> None:
        """Tools lacking annotation hints should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Delete a user from the system.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "get_data",
                    "description": "Retrieve data.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_tools_with_annotations(
        self, check: MissingToolAnnotationsCheck
    ) -> None:
        """Tools with proper annotation hints should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Returns weather data.",
                    "inputSchema": {"type": "object", "properties": {}},
                    "annotations": {
                        "readOnlyHint": True,
                        "destructiveHint": False,
                        "idempotentHint": True,
                        "openWorldHint": False,
                    },
                },
                {
                    "name": "search_users",
                    "description": "Search for users.",
                    "inputSchema": {"type": "object", "properties": {}},
                    "annotations": {
                        "readOnlyHint": True,
                        "destructiveHint": False,
                    },
                },
            ],
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_not_applicable_when_no_tools(self, check: MissingToolAnnotationsCheck) -> None:
        """No tools means no findings."""
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# AGENT-023: Conflicting Tool Names
# ==========================================================================


class TestConflictingToolNamesCheck:
    """Tests for ConflictingToolNamesCheck."""

    @pytest.fixture()
    def check(self) -> ConflictingToolNamesCheck:
        return ConflictingToolNamesCheck()

    async def test_metadata_loads_correctly(self, check: ConflictingToolNamesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent023"
        assert meta.category == "agentic_behavior"

    async def test_fails_on_conflicting_tool_names(self, check: ConflictingToolNamesCheck) -> None:
        """Tools with normalized name collisions should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_file",
                    "description": "Get a file.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "fetch_file",
                    "description": "Fetch a file.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "file" in fail_findings[0].evidence.lower()

    async def test_passes_on_distinct_tool_names(self, check: ConflictingToolNamesCheck) -> None:
        """Tools with distinct names should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "send_email",
                    "description": "Send an email.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "get_weather",
                    "description": "Get weather data.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_fails_on_exact_duplicate_names(self, check: ConflictingToolNamesCheck) -> None:
        """Exact duplicate tool names should FAIL with HIGH severity."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "read_file",
                    "description": "Read a file (v1).",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "read_file",
                    "description": "Read a file (v2).",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "duplicate" in fail_findings[0].status_extended.lower()

    async def test_not_applicable_when_fewer_than_two_tools(
        self, check: ConflictingToolNamesCheck
    ) -> None:
        """Fewer than 2 tools means no findings."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "solo_tool",
                    "description": "Only tool.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# AGENT-024: Unrestricted Tool Output
# ==========================================================================


class TestUnrestrictedToolOutputCheck:
    """Tests for UnrestrictedToolOutputCheck."""

    @pytest.fixture()
    def check(self) -> UnrestrictedToolOutputCheck:
        return UnrestrictedToolOutputCheck()

    async def test_metadata_loads_correctly(self, check: UnrestrictedToolOutputCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent024"
        assert meta.category == "agentic_behavior"

    async def test_fails_on_exfiltrative_tool_without_output_schema(
        self, check: UnrestrictedToolOutputCheck
    ) -> None:
        """Exfiltrative tool without outputSchema should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "export_all",
                    "description": "Export and returns all records from the database.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "export_all" in fail_findings[0].status_extended

    async def test_passes_on_normal_tool(self, check: UnrestrictedToolOutputCheck) -> None:
        """Tool that is not data-reading or exfiltrative should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_item",
                    "description": "Delete an item from the database.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_passes_on_read_tool_with_output_schema(
        self, check: UnrestrictedToolOutputCheck
    ) -> None:
        """Read-only tool with an outputSchema defined should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_user",
                    "description": "Get a user record.",
                    "inputSchema": {"type": "object", "properties": {}},
                    "outputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "email": {"type": "string"},
                        },
                    },
                }
            ],
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_not_applicable_when_no_tools(self, check: UnrestrictedToolOutputCheck) -> None:
        """No tools means no findings."""
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []


# ==========================================================================
# AGENT-025: Missing Sampling Capability
# ==========================================================================


class TestMissingSamplingCheck:
    """Tests for MissingSamplingCheck."""

    @pytest.fixture()
    def check(self) -> MissingSamplingCheck:
        return MissingSamplingCheck()

    async def test_metadata_loads_correctly(self, check: MissingSamplingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "agent025"
        assert meta.category == "agentic_behavior"

    async def test_fails_on_destructive_tool_without_sampling(
        self, check: MissingSamplingCheck
    ) -> None:
        """Destructive tool with no sampling capability should FAIL."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Permanently delete a user account.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
            capabilities={},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        assert "delete_user" in fail_findings[0].evidence

    async def test_passes_with_sampling_capability(self, check: MissingSamplingCheck) -> None:
        """Destructive tool with sampling capability declared should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "delete_user",
                    "description": "Permanently delete a user account.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
            capabilities={"sampling": {"enabled": True}},
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_passes_when_no_dangerous_tools(self, check: MissingSamplingCheck) -> None:
        """Non-destructive tools without sampling should PASS."""
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Get the current weather.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
            capabilities={},
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)

    async def test_not_applicable_when_no_tools(self, check: MissingSamplingCheck) -> None:
        """No tools means no findings."""
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert findings == []
