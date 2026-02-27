"""Patterns for detecting supply chain risks in package management."""

from __future__ import annotations

import re

# Version pin detection (e.g. @1.2.3 in package names)
VERSION_PIN_PATTERN: re.Pattern[str] = re.compile(r"@\d+\.\d+")

# Lockfile names indicating dependency tracking
LOCKFILE_NAMES: set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Pipfile.lock",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
    "composer.lock",
}

# SBOM (Software Bill of Materials) configuration keys
SBOM_CONFIG_KEYS: set[str] = {
    "sbom",
    "bom",
    "cyclonedx",
    "spdx",
    "software_bill_of_materials",
    "dependency_track",
    "syft",
}
