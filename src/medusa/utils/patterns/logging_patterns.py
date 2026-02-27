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

# Log rotation configuration keys
LOG_ROTATION_KEYS: set[str] = {
    "rotation",
    "rotate",
    "max_size",
    "max_files",
    "max_age",
    "retention",
    "logrotate",
    "rolling",
}

# Alerting configuration keys
ALERT_CONFIG_KEYS: set[str] = {
    "alert",
    "alerting",
    "notification",
    "webhook",
    "pagerduty",
    "opsgenie",
    "slack_webhook",
    "teams_webhook",
    "email_alert",
}

# Access logging keys
ACCESS_LOG_KEYS: set[str] = {
    "access_log",
    "access_logging",
    "request_log",
    "audit_log",
    "activity_log",
    "event_log",
}

# Log integrity keys
LOG_INTEGRITY_KEYS: set[str] = {
    "log_signing",
    "log_hash",
    "tamper_proof",
    "immutable_log",
    "worm",
    "write_once",
    "chain_of_custody",
}
