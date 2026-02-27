"""Centralized pattern library for Medusa MCP security checks.

This package splits patterns into domain-specific submodules while
re-exporting every symbol here for backwards compatibility.  Both
``from medusa.utils.patterns import X`` and
``from medusa.utils.pattern_matching import X`` continue to work.
"""

# ruff: noqa: I001
from __future__ import annotations

# -- injection / prompt poisoning -------------------------------------------
from medusa.utils.patterns.injection import (
    HIDDEN_TAG_PATTERNS,
    INJECTION_PHRASES,
    SUSPICIOUS_CODEPOINTS,
)

# -- credential detection ---------------------------------------------------
from medusa.utils.patterns.credentials import SECRET_PATTERNS

# -- network / exfiltration --------------------------------------------------
from medusa.utils.patterns.network import (
    NETWORK_TOOL_PATTERNS,
    SUSPICIOUS_PARAM_NAMES,
)

# -- schema / parameter names ------------------------------------------------
from medusa.utils.patterns.schema import (
    DATA_DUMP_PATTERNS,
    PAGINATION_PARAMS,
    PATH_PARAM_NAMES,
    SHELL_PARAM_NAMES,
    SQL_PARAM_NAMES,
)

# -- PII / identity ----------------------------------------------------------
from medusa.utils.patterns.identity import (
    GENERIC_SERVER_NAMES,
    PII_PATTERNS,
)

# -- transport / TLS ---------------------------------------------------------
from medusa.utils.patterns.transport import (
    CERT_DISABLE_CONFIG_KEYS,
    CERT_DISABLE_ENV_VARS,
    INSECURE_TLS_VERSIONS,
)

# -- logging / observability -------------------------------------------------
from medusa.utils.patterns.logging_patterns import (
    LOGGING_CONFIG_KEYS,
    LOGGING_ENV_VARS,
)

# -- supply chain ------------------------------------------------------------
from medusa.utils.patterns.supply_chain import VERSION_PIN_PATTERN

# -- filesystem / shell ------------------------------------------------------
from medusa.utils.patterns.filesystem import (
    FS_TOOL_PATTERNS,
    SENSITIVE_PATH_PATTERNS,
    SHELL_TOOL_NAMES,
)

__all__ = [
    # injection
    "HIDDEN_TAG_PATTERNS",
    "INJECTION_PHRASES",
    "SUSPICIOUS_CODEPOINTS",
    # credentials
    "SECRET_PATTERNS",
    # network
    "NETWORK_TOOL_PATTERNS",
    "SUSPICIOUS_PARAM_NAMES",
    # schema
    "DATA_DUMP_PATTERNS",
    "PAGINATION_PARAMS",
    "PATH_PARAM_NAMES",
    "SHELL_PARAM_NAMES",
    "SQL_PARAM_NAMES",
    # identity
    "GENERIC_SERVER_NAMES",
    "PII_PATTERNS",
    # transport
    "CERT_DISABLE_CONFIG_KEYS",
    "CERT_DISABLE_ENV_VARS",
    "INSECURE_TLS_VERSIONS",
    # logging
    "LOGGING_CONFIG_KEYS",
    "LOGGING_ENV_VARS",
    # supply chain
    "VERSION_PIN_PATTERN",
    # filesystem
    "FS_TOOL_PATTERNS",
    "SENSITIVE_PATH_PATTERNS",
    "SHELL_TOOL_NAMES",
]
