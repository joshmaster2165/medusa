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
