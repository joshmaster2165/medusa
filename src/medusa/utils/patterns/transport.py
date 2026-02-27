"""Patterns for detecting insecure transport, TLS, and certificate configurations."""

from __future__ import annotations

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
