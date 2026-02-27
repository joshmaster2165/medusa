"""Patterns for detecting rate limiting, throttling, and DoS mitigation configuration."""

from __future__ import annotations

# Rate limiting configuration keys
RATE_LIMIT_CONFIG_KEYS: set[str] = {
    "rate_limit",
    "ratelimit",
    "throttle",
    "throttling",
    "max_requests",
    "requests_per_second",
    "requests_per_minute",
    "quota",
    "burst",
    "concurrency",
    "max_concurrent",
}

# Rate limiting environment variable names
RATE_LIMIT_ENV_VARS: set[str] = {
    "RATE_LIMIT",
    "MAX_REQUESTS",
    "THROTTLE_LIMIT",
    "BURST_LIMIT",
    "CONCURRENCY_LIMIT",
}

# Resource limit configuration keys
RESOURCE_LIMIT_KEYS: set[str] = {
    "max_payload_size",
    "max_body_size",
    "timeout",
    "connection_timeout",
    "read_timeout",
    "write_timeout",
    "max_connections",
    "pool_size",
    "max_memory",
    "max_cpu",
}

# Backpressure and flow control configuration keys
BACKPRESSURE_KEYS: set[str] = {
    "backpressure",
    "flow_control",
    "queue_size",
    "max_queue",
    "buffer_size",
}
