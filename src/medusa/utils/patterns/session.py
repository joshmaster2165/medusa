"""Patterns for detecting session management configuration issues."""

from __future__ import annotations

# General session configuration keys
SESSION_CONFIG_KEYS: set[str] = {
    "session",
    "session_timeout",
    "session_lifetime",
    "idle_timeout",
    "max_age",
    "session_store",
    "session_secret",
    "session_cookie",
    "session_id",
}

# Session-related environment variable names
SESSION_ENV_VARS: set[str] = {
    "SESSION_SECRET",
    "SESSION_STORE",
    "SESSION_TIMEOUT",
    "COOKIE_SECRET",
    "SESSION_MAX_AGE",
}

# Session timeout configuration keys
SESSION_TIMEOUT_KEYS: set[str] = {
    "timeout",
    "ttl",
    "max_age",
    "lifetime",
    "idle_timeout",
    "absolute_timeout",
    "session_duration",
    "expires_in",
}

# Session security operation keys
SESSION_SECURITY_KEYS: set[str] = {
    "regenerate",
    "rotate",
    "invalidate",
    "destroy",
    "revoke",
    "fixation",
}
