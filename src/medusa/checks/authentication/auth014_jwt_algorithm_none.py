"""AUTH014: JWT Algorithm None Attack.

Detects JWT tokens that accept the 'none' algorithm, which disables signature verification
entirely. An attacker can forge arbitrary JWT tokens by setting the algorithm to 'none' and
removing the signature, granting themselves any identity or permission claims.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_JWT_SECTION_KEYS = {"jwt", "token", "auth"}
_ALG_KEYS = {"algorithm", "alg", "algorithms"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> list[str]:
    if depth > 10:
        return []
    hits: list[str] = []
    for k, v in config.items():
        if k.lower() in keys and isinstance(v, str):
            hits.append(v)
        elif k.lower() in keys and isinstance(v, list):
            hits.extend(str(i) for i in v)
        if isinstance(v, dict):
            hits.extend(_walk_config(v, keys, depth + 1))
    return hits


class JwtAlgorithmNoneCheck(BaseCheck):
    """JWT Algorithm None Attack."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        alg_values = _walk_config(snapshot.config_raw or {}, _ALG_KEYS)
        none_algs = [a for a in alg_values if a.lower() == "none"]
        if none_algs:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="jwt.algorithm",
                    status_extended=(
                        f"Server '{snapshot.server_name}' JWT configuration accepts the 'none' "
                        f"algorithm, disabling signature verification entirely."
                    ),
                    evidence="algorithm = 'none'",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        if alg_values:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="jwt.algorithm",
                    status_extended=(
                        f"Server '{snapshot.server_name}' JWT algorithm is configured and not"
                        f"'none'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        return []
