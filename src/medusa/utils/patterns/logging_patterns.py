"""Patterns for detecting logging, audit, and observability configurations."""

from __future__ import annotations

# Logging / audit configuration keys
LOGGING_CONFIG_KEYS: set[str] = {
    "log",
    "logging",
    "logger",
    "audit",
    "telemetry",
    "trace",
    "tracing",
    "loglevel",
    "log_level",
    "debug",
    "verbose",
    "sentry",
    "datadog",
    "newrelic",
    "splunk",
    "observability",
}

# Logging-related environment variable names
LOGGING_ENV_VARS: set[str] = {
    "LOG_LEVEL",
    "DEBUG",
    "RUST_LOG",
    "NODE_DEBUG",
    "PYTHONDEBUG",
    "SENTRY_DSN",
    "DD_TRACE_ENABLED",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_TRACES_EXPORTER",
    "NEW_RELIC_LICENSE_KEY",
}
