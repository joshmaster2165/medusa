"""DOS015: Missing Backpressure Mechanism.

Detects MCP server configurations that lack backpressure mechanisms for managing flow control
between the LLM client and the server. Without backpressure, a fast producer can overwhelm a
slow consumer, causing buffer overflows, memory exhaustion, and dropped messages.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding
from medusa.utils.pattern_matching import BACKPRESSURE_KEYS

_BACKPRESSURE_ENV = {"BACKPRESSURE_ENABLED", "FLOW_CONTROL", "QUEUE_MAX_SIZE"}


class BackpressureMissingCheck(BaseCheck):
    """Missing Backpressure Mechanism."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=BACKPRESSURE_KEYS,
            env_vars=_BACKPRESSURE_ENV,
            missing_msg=(
                "Server '{server}' has no backpressure configuration. "
                "Fast producers may overwhelm slow consumers causing buffer overflows."
            ),
            present_msg="Backpressure / flow control configuration detected in: {sources}.",
        )
