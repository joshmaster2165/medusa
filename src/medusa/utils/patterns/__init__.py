"""Pattern library for Medusa credential detection.

Only the credentials module is retained; all other scanner-specific
pattern modules have been removed.
"""

from __future__ import annotations

from medusa.utils.patterns.credentials import (
    PROVIDER_SECRET_PATTERNS,
    SECRET_PATTERNS,
    SECRET_ROTATION_KEYS,
    VAULT_CONFIG_KEYS,
)

__all__ = [
    "PROVIDER_SECRET_PATTERNS",
    "SECRET_PATTERNS",
    "SECRET_ROTATION_KEYS",
    "VAULT_CONFIG_KEYS",
]
