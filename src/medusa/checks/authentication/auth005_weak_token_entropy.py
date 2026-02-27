"""AUTH005: Weak Token Entropy.

Detects authentication tokens with insufficient randomness or entropy. Tokens generated with
weak random sources or short lengths are susceptible to brute-force attacks and prediction,
allowing attackers to forge valid authentication credentials.
"""

from __future__ import annotations

import math
import string
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_TOKEN_KEYS = {"token", "api_key", "apikey", "secret", "access_token", "auth_token", "key"}
_MIN_TOKEN_LENGTH = 32


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> list[str]:
    """Recursively walk config returning values for any matching keys."""
    if depth > 10:
        return []
    found: list[str] = []
    for k, v in config.items():
        if k.lower() in keys:
            if isinstance(v, str):
                found.append(v)
        if isinstance(v, dict):
            found.extend(_walk_config(v, keys, depth + 1))
    return found


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


class WeakTokenEntropyCheck(BaseCheck):
    """Weak Token Entropy."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        token_values: list[str] = []
        if snapshot.config_raw:
            token_values.extend(_walk_config(snapshot.config_raw, _TOKEN_KEYS))
        for key, val in snapshot.env.items():
            if key.lower() in _TOKEN_KEYS and val:
                token_values.append(val)
        weak_tokens: list[str] = []
        for token in token_values:
            if len(token) < _MIN_TOKEN_LENGTH:
                weak_tokens.append(f"short ({len(token)} chars)")
            elif _entropy(token) < 3.0 and all(c in string.digits for c in token):
                weak_tokens.append("low entropy (numeric-only)")
        if weak_tokens:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="token",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has weak token(s): "
                        f"{'; '.join(weak_tokens)}. Tokens must be at least "
                        f"{_MIN_TOKEN_LENGTH} chars of cryptographic randomness."
                    ),
                    evidence=f"Weak token indicators: {weak_tokens}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="token",
                    status_extended=(
                        f"Server '{snapshot.server_name}' token entropy appears adequate."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        return findings
