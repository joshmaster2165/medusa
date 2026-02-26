"""Unit tests for the CheckRegistry.

Tests cover:
- discover_checks() finding all checks
- Filtering by category, severity, check_id, exclude_ids
- get_categories() and get_severity_counts()
- get_check_by_id() and get_all_checks()
- Edge cases (unknown IDs, empty filters)
"""

from __future__ import annotations

import pytest

from medusa.core.check import BaseCheck
from medusa.core.models import Severity
from medusa.core.registry import CheckRegistry


@pytest.fixture()
def registry() -> CheckRegistry:
    """A fully populated CheckRegistry with all discovered checks."""
    reg = CheckRegistry()
    reg.discover_checks()
    return reg


class TestDiscoverChecks:
    """Tests for the discover_checks() method."""

    def test_discovers_at_least_one_check(self, registry: CheckRegistry) -> None:
        assert registry.check_count > 0, (
            "Registry should discover at least one check"
        )

    def test_discovers_all_expected_tool_poisoning_checks(
        self, registry: CheckRegistry
    ) -> None:
        expected_ids = {"tp001", "tp002", "tp003", "tp004", "tp005"}
        found_ids = set(registry.check_ids)
        missing = expected_ids - found_ids
        assert not missing, (
            f"Missing tool poisoning check IDs: {missing}"
        )

    def test_discovers_all_expected_input_validation_checks(
        self, registry: CheckRegistry
    ) -> None:
        expected_ids = {"iv001", "iv002", "iv003", "iv004", "iv005"}
        found_ids = set(registry.check_ids)
        missing = expected_ids - found_ids
        assert not missing, (
            f"Missing input validation check IDs: {missing}"
        )

    def test_discovers_credential_exposure_checks(
        self, registry: CheckRegistry
    ) -> None:
        expected_ids = {"cred001", "cred002", "cred003"}
        found_ids = set(registry.check_ids)
        missing = expected_ids - found_ids
        assert not missing, (
            f"Missing credential exposure check IDs: {missing}"
        )

    def test_discovers_privilege_scope_checks(
        self, registry: CheckRegistry
    ) -> None:
        expected_ids = {"priv001", "priv002", "priv003"}
        found_ids = set(registry.check_ids)
        missing = expected_ids - found_ids
        assert not missing, (
            f"Missing privilege scope check IDs: {missing}"
        )

    def test_discovers_authentication_checks(
        self, registry: CheckRegistry
    ) -> None:
        expected_ids = {"auth001", "auth002", "auth003", "auth004"}
        found_ids = set(registry.check_ids)
        missing = expected_ids - found_ids
        assert not missing, (
            f"Missing authentication check IDs: {missing}"
        )

    def test_check_ids_are_sorted(self, registry: CheckRegistry) -> None:
        ids = registry.check_ids
        assert ids == sorted(ids), "check_ids should be returned in sorted order"

    def test_total_check_count(self, registry: CheckRegistry) -> None:
        """We expect at least 20 checks across all categories."""
        assert registry.check_count >= 20, (
            f"Expected at least 20 checks, found {registry.check_count}"
        )

    def test_double_discover_does_not_duplicate(self, registry: CheckRegistry) -> None:
        """Calling discover_checks() twice should not add duplicates."""
        count_before = registry.check_count
        registry.discover_checks()
        count_after = registry.check_count
        assert count_after == count_before, (
            "Discovering checks twice should not increase the count"
        )


class TestGetChecks:
    """Tests for the get_checks() filtering method."""

    def test_filter_by_category(self, registry: CheckRegistry) -> None:
        checks = registry.get_checks(categories=["tool_poisoning"])
        assert len(checks) >= 5, (
            f"Should find at least 5 tool_poisoning checks, got {len(checks)}"
        )
        for check in checks:
            meta = check.metadata()
            assert meta.category == "tool_poisoning", (
                f"Check {meta.check_id} should be in tool_poisoning category"
            )

    def test_filter_by_severity(self, registry: CheckRegistry) -> None:
        checks = registry.get_checks(severities=["critical"])
        assert len(checks) >= 1, "Should find at least one CRITICAL check"
        for check in checks:
            meta = check.metadata()
            assert meta.severity == Severity.CRITICAL, (
                f"Check {meta.check_id} should be CRITICAL severity"
            )

    def test_filter_by_check_ids(self, registry: CheckRegistry) -> None:
        checks = registry.get_checks(check_ids=["tp001", "iv001"])
        assert len(checks) == 2, (
            f"Should find exactly 2 checks for tp001 and iv001, got {len(checks)}"
        )
        found_ids = {c.metadata().check_id for c in checks}
        assert found_ids == {"tp001", "iv001"}, (
            f"Expected tp001 and iv001, got {found_ids}"
        )

    def test_exclude_ids(self, registry: CheckRegistry) -> None:
        all_checks = registry.get_all_checks()
        excluded = registry.get_checks(exclude_ids=["tp001", "tp002"])
        excluded_ids = {c.metadata().check_id for c in excluded}
        assert "tp001" not in excluded_ids, "tp001 should be excluded"
        assert "tp002" not in excluded_ids, "tp002 should be excluded"
        assert len(excluded) == len(all_checks) - 2, (
            "Excluding 2 checks should reduce total by 2"
        )

    def test_filter_by_multiple_categories(self, registry: CheckRegistry) -> None:
        checks = registry.get_checks(
            categories=["tool_poisoning", "input_validation"]
        )
        assert len(checks) >= 10, (
            "Should find at least 10 checks across two categories"
        )
        categories = {c.metadata().category for c in checks}
        assert categories <= {"tool_poisoning", "input_validation"}, (
            f"Unexpected categories in result: {categories}"
        )

    def test_filter_returns_instances(self, registry: CheckRegistry) -> None:
        checks = registry.get_checks(check_ids=["tp001"])
        assert len(checks) == 1, "Should find exactly one check"
        assert isinstance(checks[0], BaseCheck), (
            "Returned check should be a BaseCheck instance"
        )

    def test_no_matching_filter_returns_empty(self, registry: CheckRegistry) -> None:
        checks = registry.get_checks(check_ids=["nonexistent_check_id"])
        assert len(checks) == 0, (
            "Non-matching check_ids filter should return empty list"
        )

    def test_no_filters_returns_all(self, registry: CheckRegistry) -> None:
        checks = registry.get_checks()
        assert len(checks) == registry.check_count, (
            "No filters should return all checks"
        )


class TestGetCheckById:
    """Tests for get_check_by_id()."""

    def test_known_check_returns_instance(self, registry: CheckRegistry) -> None:
        check = registry.get_check_by_id("tp001")
        assert check is not None, "tp001 should be found"
        assert isinstance(check, BaseCheck), "Should return a BaseCheck instance"
        assert check.metadata().check_id == "tp001", "Should return tp001"

    def test_unknown_check_returns_none(self, registry: CheckRegistry) -> None:
        check = registry.get_check_by_id("zzz999")
        assert check is None, "Unknown check ID should return None"


class TestGetAllChecks:
    """Tests for get_all_checks()."""

    def test_returns_all_registered_checks(self, registry: CheckRegistry) -> None:
        all_checks = registry.get_all_checks()
        assert len(all_checks) == registry.check_count, (
            "get_all_checks() should return the same count as check_count"
        )

    def test_all_are_base_check_instances(self, registry: CheckRegistry) -> None:
        for check in registry.get_all_checks():
            assert isinstance(check, BaseCheck), (
                f"{type(check).__name__} is not a BaseCheck instance"
            )


class TestGetCategories:
    """Tests for get_categories()."""

    def test_returns_known_categories(self, registry: CheckRegistry) -> None:
        categories = registry.get_categories()
        expected_subset = {
            "tool_poisoning",
            "input_validation",
            "credential_exposure",
            "privilege_scope",
            "authentication",
        }
        missing = expected_subset - set(categories)
        assert not missing, (
            f"Missing expected categories: {missing}"
        )

    def test_categories_are_sorted(self, registry: CheckRegistry) -> None:
        categories = registry.get_categories()
        assert categories == sorted(categories), (
            "Categories should be returned in sorted order"
        )

    def test_categories_are_unique(self, registry: CheckRegistry) -> None:
        categories = registry.get_categories()
        assert len(categories) == len(set(categories)), (
            "Categories list should have no duplicates"
        )


class TestGetSeverityCounts:
    """Tests for get_severity_counts()."""

    def test_returns_dict_of_severity_counts(self, registry: CheckRegistry) -> None:
        counts = registry.get_severity_counts()
        assert isinstance(counts, dict), "Should return a dict"
        assert len(counts) >= 1, "Should have at least one severity level"

    def test_counts_are_positive(self, registry: CheckRegistry) -> None:
        counts = registry.get_severity_counts()
        for severity, count in counts.items():
            assert count > 0, f"Count for {severity} should be positive"

    def test_total_matches_check_count(self, registry: CheckRegistry) -> None:
        counts = registry.get_severity_counts()
        total = sum(counts.values())
        assert total == registry.check_count, (
            f"Sum of severity counts ({total}) should equal total check "
            f"count ({registry.check_count})"
        )

    def test_known_severities_present(self, registry: CheckRegistry) -> None:
        counts = registry.get_severity_counts()
        # We expect at least critical and high to have checks
        assert "critical" in counts, "Should have at least one CRITICAL check"
        assert "high" in counts, "Should have at least one HIGH check"

    def test_severity_values_are_valid(self, registry: CheckRegistry) -> None:
        counts = registry.get_severity_counts()
        valid_values = {s.value for s in Severity}
        for severity_key in counts:
            assert severity_key in valid_values, (
                f"Unexpected severity key: {severity_key}"
            )


class TestEmptyRegistry:
    """Tests for a registry before discover_checks() is called."""

    def test_empty_registry_has_zero_checks(self) -> None:
        reg = CheckRegistry()
        assert reg.check_count == 0, "New registry should have 0 checks"

    def test_empty_registry_check_ids_is_empty(self) -> None:
        reg = CheckRegistry()
        assert reg.check_ids == [], "New registry should have empty check_ids"

    def test_empty_registry_get_all_checks_is_empty(self) -> None:
        reg = CheckRegistry()
        assert reg.get_all_checks() == [], (
            "New registry get_all_checks() should return empty list"
        )

    def test_empty_registry_get_categories_is_empty(self) -> None:
        reg = CheckRegistry()
        assert reg.get_categories() == [], (
            "New registry get_categories() should return empty list"
        )

    def test_empty_registry_get_severity_counts_is_empty(self) -> None:
        reg = CheckRegistry()
        assert reg.get_severity_counts() == {}, (
            "New registry get_severity_counts() should return empty dict"
        )

    def test_empty_registry_get_check_by_id_returns_none(self) -> None:
        reg = CheckRegistry()
        assert reg.get_check_by_id("tp001") is None, (
            "Undiscovered registry should return None for any check ID"
        )
