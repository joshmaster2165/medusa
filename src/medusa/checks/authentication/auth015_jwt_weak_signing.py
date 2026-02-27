"""AUTH015: JWT Weak Signing Key.

Detects JWT tokens signed with weak or short symmetric keys that are vulnerable to brute-force
or dictionary attacks. Short HMAC secrets can be cracked offline, allowing an attacker to forge
valid tokens.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.authentication import WEAK_JWT_ALGORITHMS

_HTTP_TRANSPORTS = {"http", "sse"}
_ALG_KEYS = {"algorithm", "alg", "algorithms"}
_SECRET_KEYS = {"secret", "signing_key", "jwt_secret", "hmac_secret"}
_MIN_SECRET_LENGTH = 32


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> list[tuple[str, str]]:
    """Return (key, value) pairs matching keys."""
    if depth > 10:
        return []
    hits: list[tuple[str, str]] = []
    for k, v in config.items():
        if k.lower() in keys and isinstance(v, str):
            hits.append((k, v))
        if isinstance(v, dict):
            hits.extend(_walk_config(v, keys, depth + 1))
    return hits


class JwtWeakSigningCheck(BaseCheck):
    """JWT Weak Signing Key."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        alg_pairs = _walk_config(snapshot.config_raw or {}, _ALG_KEYS)
        secret_pairs = _walk_config(snapshot.config_raw or {}, _SECRET_KEYS)
        weak_algs = [
            v for _, v in alg_pairs if v.upper() in {a.upper() for a in WEAK_JWT_ALGORITHMS}
        ]
        weak_secrets = [(k, v) for k, v in secret_pairs if len(v) < _MIN_SECRET_LENGTH]
        if weak_algs or weak_secrets:
            issues: list[str] = []
            if weak_algs:
                issues.append(f"weak algorithm(s): {', '.join(weak_algs)}")
            if weak_secrets:
                issues.append(
                    f"short secret(s) ({weak_secrets[0][1][:4]}... < {_MIN_SECRET_LENGTH} chars)"
                )
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="jwt.signing",
                    status_extended=(
                        f"Server '{snapshot.server_name}' JWT signing is weak: {'; '.join(issues)}."
                    ),
                    evidence="; ".join(issues),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        # JWT config exists but no weakness found
        if alg_pairs or secret_pairs:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="jwt.signing",
                    status_extended=(
                        f"Server '{snapshot.server_name}' JWT signing configuration appears strong."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        return []
