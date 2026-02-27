"""Patterns for detecting error handling, debug mode, and information disclosure risks."""

from __future__ import annotations

# Debug mode configuration keys
DEBUG_CONFIG_KEYS: set[str] = {
    "debug",
    "debug_mode",
    "development",
    "dev_mode",
    "verbose",
    "trace",
    "profiling",
    "diagnostic",
}

# Debug mode environment variable names
DEBUG_ENV_VARS: set[str] = {
    "DEBUG",
    "NODE_ENV",
    "FLASK_DEBUG",
    "DJANGO_DEBUG",
    "RAILS_ENV",
    "APP_DEBUG",
    "ASPNETCORE_ENVIRONMENT",
}

# Error exposure configuration keys
ERROR_EXPOSURE_KEYS: set[str] = {
    "stack_trace",
    "stacktrace",
    "show_errors",
    "display_errors",
    "error_detail",
    "detailed_errors",
    "include_stacktrace",
}

# Error handling configuration keys
ERROR_HANDLING_KEYS: set[str] = {
    "error_handler",
    "exception_handler",
    "error_page",
    "error_template",
    "graceful_degradation",
    "fallback",
    "circuit_breaker",
}
