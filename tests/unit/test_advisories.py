"""Unit tests for the Medusa Advisory Database."""

from __future__ import annotations

import pytest

from medusa.advisories.models import Advisory
from medusa.advisories.loader import (
    load_all_advisories,
    get_advisory,
    get_advisories_for_check,
    get_advisories_by_severity,
    get_advisories_by_tag,
)


class TestAdvisoryModel:
    """Tests for the Advisory data model."""

    def test_advisory_creation(self) -> None:
        """Advisory should be created with required fields and sensible defaults."""
        a = Advisory(
            id="MAD-2025-9999",
            title="Test Advisory",
            severity="high",
            description="Test description",
            affected_tools_pattern="test*",
            attack_vector="Network",
            impact="Test impact",
            published_date="2025-01-01",
        )
        assert a.id == "MAD-2025-9999"
        assert a.severity == "high"
        assert a.related_checks == []
        assert a.tags == []
        assert a.cwe == []
        assert a.owasp_mcp == []
        assert a.references == []

    def test_advisory_with_all_fields(self) -> None:
        """Advisory with all optional fields should retain them."""
        a = Advisory(
            id="MAD-2025-9999",
            title="Test",
            severity="critical",
            description="Desc",
            affected_tools_pattern="*",
            attack_vector="Local",
            impact="High",
            references=["https://example.com"],
            related_checks=["tp001", "tp002"],
            owasp_mcp=["MCP03:2025"],
            published_date="2025-01-01",
            cwe=["CWE-94"],
            tags=["injection"],
        )
        assert len(a.references) == 1
        assert len(a.related_checks) == 2
        assert a.owasp_mcp == ["MCP03:2025"]
        assert a.cwe == ["CWE-94"]
        assert a.tags == ["injection"]

    def test_advisory_severity_values(self) -> None:
        """Advisory should accept any severity string (validation is in loader)."""
        for sev in ("critical", "high", "medium", "low"):
            a = Advisory(
                id="MAD-2025-9999",
                title="Test",
                severity=sev,
                description="Desc",
                affected_tools_pattern="*",
                attack_vector="Network",
                impact="Impact",
                published_date="2025-01-01",
            )
            assert a.severity == sev


class TestAdvisoryLoader:
    """Tests for loading advisories from YAML files."""

    def test_load_all_advisories(self) -> None:
        """Should load exactly 10 advisories as a tuple."""
        advisories = load_all_advisories()
        assert len(advisories) == 10
        assert all(isinstance(a, Advisory) for a in advisories)

    def test_advisory_ids_sequential(self) -> None:
        """Advisory IDs should be MAD-2025-0001 through MAD-2025-0010."""
        advisories = load_all_advisories()
        for i, a in enumerate(advisories, start=1):
            assert a.id == f"MAD-2025-{i:04d}"

    def test_get_advisory_by_id(self) -> None:
        """Should retrieve a specific advisory by its ID."""
        a = get_advisory("MAD-2025-0001")
        assert a is not None
        assert a.id == "MAD-2025-0001"
        assert "tool poisoning" in a.title.lower() or "hidden" in a.title.lower()

    def test_get_advisory_nonexistent(self) -> None:
        """Non-existent advisory ID should return None."""
        a = get_advisory("MAD-2025-9999")
        assert a is None

    def test_get_advisories_for_check(self) -> None:
        """Should find advisories that reference a given check ID."""
        results = get_advisories_for_check("tp001")
        assert len(results) >= 1
        assert all("tp001" in a.related_checks for a in results)

    def test_get_advisories_for_check_no_match(self) -> None:
        """Non-existent check ID should return empty list."""
        results = get_advisories_for_check("nonexistent999")
        assert results == []

    def test_get_advisories_by_severity_high(self) -> None:
        """Should find at least one 'high' severity advisory."""
        results = get_advisories_by_severity("high")
        assert len(results) >= 1
        assert all(a.severity == "high" for a in results)

    def test_get_advisories_by_severity_critical(self) -> None:
        """Should find at least one 'critical' severity advisory."""
        results = get_advisories_by_severity("critical")
        assert len(results) >= 1
        assert all(a.severity == "critical" for a in results)

    def test_get_advisories_by_severity_medium(self) -> None:
        """Should find at least one 'medium' severity advisory."""
        results = get_advisories_by_severity("medium")
        assert len(results) >= 1
        assert all(a.severity == "medium" for a in results)

    def test_get_advisories_by_tag(self) -> None:
        """Should find advisories matching a known tag."""
        all_advisories = load_all_advisories()
        # Find a tag from the first advisory that has tags
        some_tag = None
        for a in all_advisories:
            if a.tags:
                some_tag = a.tags[0]
                break
        assert some_tag is not None, "At least one advisory should have tags"
        results = get_advisories_by_tag(some_tag)
        assert len(results) >= 1
        assert all(some_tag in a.tags for a in results)

    def test_get_advisories_by_tag_no_match(self) -> None:
        """Non-existent tag should return empty list."""
        results = get_advisories_by_tag("nonexistent_tag_xyz_12345")
        assert results == []

    def test_all_advisories_have_required_fields(self) -> None:
        """Every advisory must have all required fields populated."""
        for a in load_all_advisories():
            assert a.id, f"Advisory missing id"
            assert a.title, f"{a.id} missing title"
            assert a.severity in ("critical", "high", "medium", "low"), (
                f"{a.id} has invalid severity: {a.severity}"
            )
            assert a.description, f"{a.id} missing description"
            assert a.attack_vector, f"{a.id} missing attack_vector"
            assert a.impact, f"{a.id} missing impact"
            assert a.published_date, f"{a.id} missing published_date"
            assert len(a.related_checks) >= 1, f"{a.id} missing related_checks"

    def test_all_advisories_have_owasp_mcp(self) -> None:
        """Every advisory should reference at least one OWASP MCP category."""
        for a in load_all_advisories():
            assert len(a.owasp_mcp) >= 1, f"{a.id} missing owasp_mcp"

    def test_all_advisories_have_tags(self) -> None:
        """Every advisory should have at least one tag."""
        for a in load_all_advisories():
            assert len(a.tags) >= 1, f"{a.id} missing tags"

    def test_all_advisories_have_cwe(self) -> None:
        """Every advisory should reference at least one CWE."""
        for a in load_all_advisories():
            assert len(a.cwe) >= 1, f"{a.id} missing CWE references"

    def test_advisory_id_format(self) -> None:
        """All advisory IDs should match the MAD-YYYY-NNNN format."""
        import re
        pattern = re.compile(r"^MAD-\d{4}-\d{4}$")
        for a in load_all_advisories():
            assert pattern.match(a.id), f"Invalid advisory ID format: {a.id}"

    def test_load_all_advisories_cached(self) -> None:
        """Repeated calls should return the same tuple object (lru_cache)."""
        first = load_all_advisories()
        second = load_all_advisories()
        assert first is second, "load_all_advisories should be cached"
