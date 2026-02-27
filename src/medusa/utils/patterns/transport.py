"""Patterns for detecting insecure transport, TLS, and certificate configurations."""

from __future__ import annotations

import re

# Certificate validation disable config keys
CERT_DISABLE_CONFIG_KEYS: set[str] = {
    "verify",
    "ssl_verify",
    "tls_verify",
    "insecure",
    "skip_verify",
    "skipverify",
    "rejectunauthorized",
    "check_certificate",
    "strict_ssl",
    "strictssl",
}

# Certificate validation disable environment variables
CERT_DISABLE_ENV_VARS: set[str] = {
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "PYTHONHTTPSVERIFY",
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_NO_VERIFY",
}

# Deprecated / insecure TLS versions
INSECURE_TLS_VERSIONS: set[str] = {
    "sslv2",
    "sslv3",
    "ssl2",
    "ssl3",
    "tls1.0",
    "tls1.1",
    "tlsv1",
    "tlsv1.0",
    "tlsv1.1",
}

# Weak cipher suite patterns
WEAK_CIPHER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(RC4|DES|3DES|MD5|NULL|EXPORT|anon)", re.IGNORECASE),
    re.compile(r"TLS_RSA_WITH", re.IGNORECASE),  # Non-PFS ciphers
]

# HSTS configuration keys
HSTS_CONFIG_KEYS: set[str] = {
    "hsts",
    "strict_transport_security",
    "max_age",
    "includesubdomains",
    "preload",
}

# CORS configuration keys
CORS_CONFIG_KEYS: set[str] = {
    "cors",
    "access_control_allow_origin",
    "allowed_origins",
    "cors_origins",
    "cors_methods",
    "cors_headers",
}

# Content Security Policy keys
CSP_CONFIG_KEYS: set[str] = {
    "csp",
    "content_security_policy",
    "default_src",
    "script_src",
    "style_src",
    "img_src",
}
