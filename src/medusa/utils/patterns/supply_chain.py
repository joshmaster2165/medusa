"""Patterns for detecting supply chain risks in package management."""

from __future__ import annotations

import re

# Version pin detection (e.g. @1.2.3 in package names)
VERSION_PIN_PATTERN: re.Pattern[str] = re.compile(r"@\d+\.\d+")
