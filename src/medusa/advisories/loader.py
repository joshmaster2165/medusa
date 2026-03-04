"""Loader and query functions for the Medusa Advisory Database."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from medusa.advisories.models import Advisory


def _advisories_dir() -> Path:
    return Path(__file__).parent


@lru_cache(maxsize=1)
def load_all_advisories() -> tuple[Advisory, ...]:
    """Load all advisory YAML files. Results are cached."""
    advisories_dir = _advisories_dir()
    advisories = []
    for yaml_file in sorted(advisories_dir.glob("MAD-*.yaml")):
        data = yaml.safe_load(yaml_file.read_text())
        advisories.append(Advisory(**data))
    return tuple(advisories)


def get_advisory(advisory_id: str) -> Advisory | None:
    """Load a single advisory by ID."""
    path = _advisories_dir() / f"{advisory_id}.yaml"
    if not path.exists():
        return None
    data = yaml.safe_load(path.read_text())
    return Advisory(**data)


def get_advisories_for_check(check_id: str) -> list[Advisory]:
    """Return all advisories that reference a specific check ID."""
    return [a for a in load_all_advisories() if check_id in a.related_checks]


def get_advisories_by_severity(severity: str) -> list[Advisory]:
    """Return all advisories matching a severity level."""
    return [a for a in load_all_advisories() if a.severity == severity.lower()]


def get_advisories_by_tag(tag: str) -> list[Advisory]:
    """Return all advisories containing a specific tag."""
    return [a for a in load_all_advisories() if tag in a.tags]
