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
    BASE64_PATTERN,
    CAPABILITY_ESCALATION_KEYWORDS,
    ENCODING_BYPASS_PATTERNS,
    HIDDEN_TAG_PATTERNS,
    INJECTION_PHRASES,
    JAILBREAK_PATTERNS,
    MARKDOWN_INJECTION_PATTERNS,
    SUSPICIOUS_CODEPOINTS,
    URL_INJECTION_PATTERNS,
)

# -- credential detection ---------------------------------------------------
from medusa.utils.patterns.credentials import (
    PROVIDER_SECRET_PATTERNS,
    SECRET_PATTERNS,
    SECRET_ROTATION_KEYS,
    VAULT_CONFIG_KEYS,
)

# -- network / exfiltration --------------------------------------------------
from medusa.utils.patterns.network import (
    NETWORK_TOOL_PATTERNS,
    SUSPICIOUS_PARAM_NAMES,
)

# -- schema / parameter names ------------------------------------------------
from medusa.utils.patterns.schema import (
    CSV_PARAM_NAMES,
    DATA_DUMP_PATTERNS,
    EMAIL_PARAM_NAMES,
    ENV_PARAM_NAMES,
    FILE_PARAM_NAMES,
    HEADER_PARAM_NAMES,
    LDAP_PARAM_NAMES,
    NOSQL_PARAM_NAMES,
    PAGINATION_PARAMS,
    PATH_PARAM_NAMES,
    SHELL_PARAM_NAMES,
    SQL_PARAM_NAMES,
    TEMPLATE_PARAM_NAMES,
    URL_PARAM_NAMES,
    XML_PARAM_NAMES,
    XPATH_PARAM_NAMES,
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
    CORS_CONFIG_KEYS,
    CSP_CONFIG_KEYS,
    HSTS_CONFIG_KEYS,
    INSECURE_TLS_VERSIONS,
    WEAK_CIPHER_PATTERNS,
)

# -- logging / observability -------------------------------------------------
from medusa.utils.patterns.logging_patterns import (
    ACCESS_LOG_KEYS,
    ALERT_CONFIG_KEYS,
    LOG_INTEGRITY_KEYS,
    LOG_ROTATION_KEYS,
    LOGGING_CONFIG_KEYS,
    LOGGING_ENV_VARS,
)

# -- supply chain ------------------------------------------------------------
from medusa.utils.patterns.supply_chain import (
    LOCKFILE_NAMES,
    SBOM_CONFIG_KEYS,
    VERSION_PIN_PATTERN,
)

# -- filesystem / shell ------------------------------------------------------
from medusa.utils.patterns.filesystem import (
    ADMIN_TOOL_PATTERNS,
    DESTRUCTIVE_TOOL_PATTERNS,
    FS_TOOL_PATTERNS,
    SENSITIVE_PATH_PATTERNS,
    SHELL_TOOL_NAMES,
)

# -- SSRF / network ----------------------------------------------------------
from medusa.utils.patterns.ssrf import (
    CLOUD_METADATA_URLS,
    DANGEROUS_SCHEMES,
    INTERNAL_SERVICE_PATTERNS,
    LOCALHOST_PATTERNS,
    PRIVATE_IP_RANGES,
    URL_PARAM_NAMES as SSRF_URL_PARAM_NAMES,
)

# -- authentication ----------------------------------------------------------
from medusa.utils.patterns.authentication import (
    AUTH_CONFIG_KEYS,
    AUTH_HEADER_NAMES,
    COOKIE_SECURITY_FLAGS,
    CSRF_CONFIG_KEYS,
    JWT_CONFIG_KEYS,
    MFA_CONFIG_KEYS,
    OAUTH_CONFIG_KEYS,
    WEAK_JWT_ALGORITHMS,
)

# -- session management ------------------------------------------------------
from medusa.utils.patterns.session import (
    SESSION_CONFIG_KEYS,
    SESSION_ENV_VARS,
    SESSION_SECURITY_KEYS,
    SESSION_TIMEOUT_KEYS,
)

# -- agentic behavior --------------------------------------------------------
from medusa.utils.patterns.agentic import (
    AGENT_SAFETY_CONFIG_KEYS,
    CONFIRMATION_CONFIG_KEYS,
    DELEGATION_KEYWORDS,
    DESTRUCTIVE_ACTION_KEYWORDS,
    LOOP_DETECTION_KEYWORDS,
)

# -- governance --------------------------------------------------------------
from medusa.utils.patterns.governance_patterns import (
    CHANGE_MANAGEMENT_KEYS,
    COMPLIANCE_CONFIG_KEYS,
    DATA_GOVERNANCE_KEYS,
    GOVERNANCE_AUDIT_KEYS,
    INCIDENT_RESPONSE_KEYS,
    POLICY_CONFIG_KEYS,
    VENDOR_ASSESSMENT_KEYS,
)

# -- rate limiting -----------------------------------------------------------
from medusa.utils.patterns.rate_limiting_patterns import (
    BACKPRESSURE_KEYS,
    RATE_LIMIT_CONFIG_KEYS,
    RATE_LIMIT_ENV_VARS,
    RESOURCE_LIMIT_KEYS,
)

# -- error handling ----------------------------------------------------------
from medusa.utils.patterns.error_handling_patterns import (
    DEBUG_CONFIG_KEYS,
    DEBUG_ENV_VARS,
    ERROR_EXPOSURE_KEYS,
    ERROR_HANDLING_KEYS,
)

__all__ = [
    # injection
    "BASE64_PATTERN",
    "CAPABILITY_ESCALATION_KEYWORDS",
    "ENCODING_BYPASS_PATTERNS",
    "HIDDEN_TAG_PATTERNS",
    "INJECTION_PHRASES",
    "JAILBREAK_PATTERNS",
    "MARKDOWN_INJECTION_PATTERNS",
    "SUSPICIOUS_CODEPOINTS",
    "URL_INJECTION_PATTERNS",
    # credentials
    "PROVIDER_SECRET_PATTERNS",
    "SECRET_PATTERNS",
    "SECRET_ROTATION_KEYS",
    "VAULT_CONFIG_KEYS",
    # network
    "NETWORK_TOOL_PATTERNS",
    "SUSPICIOUS_PARAM_NAMES",
    # schema
    "CSV_PARAM_NAMES",
    "DATA_DUMP_PATTERNS",
    "EMAIL_PARAM_NAMES",
    "ENV_PARAM_NAMES",
    "FILE_PARAM_NAMES",
    "HEADER_PARAM_NAMES",
    "LDAP_PARAM_NAMES",
    "NOSQL_PARAM_NAMES",
    "PAGINATION_PARAMS",
    "PATH_PARAM_NAMES",
    "SHELL_PARAM_NAMES",
    "SQL_PARAM_NAMES",
    "TEMPLATE_PARAM_NAMES",
    "URL_PARAM_NAMES",
    "XML_PARAM_NAMES",
    "XPATH_PARAM_NAMES",
    # identity
    "GENERIC_SERVER_NAMES",
    "PII_PATTERNS",
    # transport
    "CERT_DISABLE_CONFIG_KEYS",
    "CERT_DISABLE_ENV_VARS",
    "CORS_CONFIG_KEYS",
    "CSP_CONFIG_KEYS",
    "HSTS_CONFIG_KEYS",
    "INSECURE_TLS_VERSIONS",
    "WEAK_CIPHER_PATTERNS",
    # logging
    "ACCESS_LOG_KEYS",
    "ALERT_CONFIG_KEYS",
    "LOG_INTEGRITY_KEYS",
    "LOG_ROTATION_KEYS",
    "LOGGING_CONFIG_KEYS",
    "LOGGING_ENV_VARS",
    # supply chain
    "LOCKFILE_NAMES",
    "SBOM_CONFIG_KEYS",
    "VERSION_PIN_PATTERN",
    # filesystem
    "ADMIN_TOOL_PATTERNS",
    "DESTRUCTIVE_TOOL_PATTERNS",
    "FS_TOOL_PATTERNS",
    "SENSITIVE_PATH_PATTERNS",
    "SHELL_TOOL_NAMES",
    # ssrf
    "CLOUD_METADATA_URLS",
    "DANGEROUS_SCHEMES",
    "INTERNAL_SERVICE_PATTERNS",
    "LOCALHOST_PATTERNS",
    "PRIVATE_IP_RANGES",
    "SSRF_URL_PARAM_NAMES",
    # authentication
    "AUTH_CONFIG_KEYS",
    "AUTH_HEADER_NAMES",
    "COOKIE_SECURITY_FLAGS",
    "CSRF_CONFIG_KEYS",
    "JWT_CONFIG_KEYS",
    "MFA_CONFIG_KEYS",
    "OAUTH_CONFIG_KEYS",
    "WEAK_JWT_ALGORITHMS",
    # session
    "SESSION_CONFIG_KEYS",
    "SESSION_ENV_VARS",
    "SESSION_SECURITY_KEYS",
    "SESSION_TIMEOUT_KEYS",
    # agentic
    "AGENT_SAFETY_CONFIG_KEYS",
    "CONFIRMATION_CONFIG_KEYS",
    "DELEGATION_KEYWORDS",
    "DESTRUCTIVE_ACTION_KEYWORDS",
    "LOOP_DETECTION_KEYWORDS",
    # governance
    "CHANGE_MANAGEMENT_KEYS",
    "COMPLIANCE_CONFIG_KEYS",
    "DATA_GOVERNANCE_KEYS",
    "GOVERNANCE_AUDIT_KEYS",
    "INCIDENT_RESPONSE_KEYS",
    "POLICY_CONFIG_KEYS",
    "VENDOR_ASSESSMENT_KEYS",
    # rate limiting
    "BACKPRESSURE_KEYS",
    "RATE_LIMIT_CONFIG_KEYS",
    "RATE_LIMIT_ENV_VARS",
    "RESOURCE_LIMIT_KEYS",
    # error handling
    "DEBUG_CONFIG_KEYS",
    "DEBUG_ENV_VARS",
    "ERROR_EXPOSURE_KEYS",
    "ERROR_HANDLING_KEYS",
]
