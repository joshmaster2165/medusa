"""Patterns for detecting agentic behavior and autonomous action risks."""

from __future__ import annotations

# Keywords indicating destructive or irreversible actions
DESTRUCTIVE_ACTION_KEYWORDS: set[str] = {
    "delete",
    "remove",
    "drop",
    "truncate",
    "destroy",
    "purge",
    "wipe",
    "erase",
    "format",
    "kill",
    "terminate",
    "shutdown",
    "reboot",
    "reset",
}

# Configuration keys for human-in-the-loop confirmation
CONFIRMATION_CONFIG_KEYS: set[str] = {
    "confirm",
    "confirmation",
    "approve",
    "approval",
    "human_in_loop",
    "human_in_the_loop",
    "require_approval",
    "manual_review",
    "interactive",
}

# Safety configuration keys for autonomous agents
AGENT_SAFETY_CONFIG_KEYS: set[str] = {
    "max_iterations",
    "max_steps",
    "max_depth",
    "recursion_limit",
    "loop_limit",
    "timeout",
    "rate_limit",
    "max_retries",
    "circuit_breaker",
    "safety",
}

# Keywords related to loop and recursion detection
LOOP_DETECTION_KEYWORDS: set[str] = {
    "loop",
    "recursion",
    "recursive",
    "iteration",
    "cycle",
    "repeat",
    "retry",
    "backoff",
}

# Keywords related to delegation and chaining
DELEGATION_KEYWORDS: set[str] = {
    "delegate",
    "forward",
    "proxy",
    "relay",
    "invoke",
    "call",
    "chain",
    "orchestrate",
    "spawn",
}

# Schema-level confirmation parameters (for tool inputSchema.properties inspection)
CONFIRMATION_SCHEMA_PARAMS: set[str] = {
    "confirm",
    "confirmation",
    "dry_run",
    "dryrun",
    "dry-run",
    "force",
    "yes",
    "approve",
    "simulate",
    "preview",
    "test_mode",
    "safe_mode",
    "no_op",
    "noop",
    "check_only",
}

# Schema-level rate limiting parameters
RATE_LIMIT_SCHEMA_PARAMS: set[str] = {
    "rate_limit",
    "max_calls",
    "throttle",
    "cooldown",
    "max_per_minute",
    "max_per_hour",
    "requests_per_second",
}

# Schema parameters that enable recursion/looping
RECURSION_PARAMS: set[str] = {
    "depth",
    "max_depth",
    "max_iterations",
    "level",
    "recursive",
    "iterations",
    "max_recursion",
    "recursion_depth",
    "max_steps",
}

# Schema-level auth/credential parameters
AUTH_SCHEMA_PARAMS: set[str] = {
    "auth",
    "token",
    "credential",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "secret",
    "password",
    "auth_token",
    "access_token",
    "session_token",
}
