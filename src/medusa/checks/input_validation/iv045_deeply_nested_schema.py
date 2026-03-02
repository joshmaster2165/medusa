"""IV045: Deeply Nested Schema.

Detects tool schemas with excessive nesting depth where objects contain objects that
contain further objects. Deeply nested schemas increase parsing overhead, make
comprehensive validation difficult, and can be exploited for amplification attacks
or to hide malicious payloads in deeply buried properties.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_MAX_SAFE_DEPTH: int = 5
_RECURSION_LIMIT: int = 10


def _max_depth(
    schema: dict, depth: int = 0, max_d: int = 10
) -> int:
    """Recursively measure nesting depth of a JSON Schema.

    Walks properties and items to find the deepest nesting level.
    Uses max_d to prevent infinite loops from circular references.
    """
    if not isinstance(schema, dict):
        return depth

    if depth >= max_d:
        return depth

    result = depth

    # Check properties of objects
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for prop_def in properties.values():
            if not isinstance(prop_def, dict):
                continue
            prop_type = prop_def.get("type", "")
            if prop_type == "object" or prop_def.get(
                "properties"
            ):
                result = max(
                    result,
                    _max_depth(
                        prop_def, depth + 1, max_d
                    ),
                )
            elif prop_type == "array":
                items = prop_def.get("items")
                if isinstance(items, dict) and (
                    items.get("type") == "object"
                    or items.get("properties")
                ):
                    result = max(
                        result,
                        _max_depth(
                            items, depth + 1, max_d
                        ),
                    )

    # Check array items at current level
    items = schema.get("items")
    if isinstance(items, dict) and (
        items.get("type") == "object"
        or items.get("properties")
    ):
        result = max(
            result,
            _max_depth(items, depth + 1, max_d),
        )

    # Recurse into anyOf / oneOf / allOf combiners
    for combiner in ("anyOf", "oneOf", "allOf"):
        combiner_list = schema.get(combiner)
        if isinstance(combiner_list, list):
            for sub in combiner_list:
                if isinstance(sub, dict):
                    result = max(
                        result,
                        _max_depth(sub, depth, max_d),
                    )

    return result


def _has_ref(schema: dict) -> bool:
    """Check if a schema contains $ref keys suggesting recursion."""
    if not isinstance(schema, dict):
        return False
    if "$ref" in schema:
        return True
    for val in schema.values():
        if isinstance(val, dict) and _has_ref(val):
            return True
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and _has_ref(item):
                    return True
    return False


class DeeplyNestedSchemaCheck(BaseCheck):
    """Deeply Nested Schema."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            input_schema: dict | None = tool.get("inputSchema")

            if not input_schema or not isinstance(input_schema, dict):
                continue

            depth = _max_depth(input_schema)
            has_ref = _has_ref(input_schema)
            too_deep = depth > _MAX_SAFE_DEPTH

            if not too_deep and not has_ref:
                continue

            issues = []
            if too_deep:
                issues.append(
                    f"depth={depth} > {_MAX_SAFE_DEPTH}"
                )
            if has_ref:
                issues.append("contains $ref (recursion)")

            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="tool",
                    resource_name=tool_name,
                    status_extended=(
                        f"Tool '{tool_name}' input schema "
                        f"has structural risk: "
                        f"{'; '.join(issues)}. This can "
                        f"cause resource exhaustion and "
                        f"makes validation harder."
                    ),
                    evidence=(
                        f"tool={tool_name}, "
                        f"measured_depth={depth}, "
                        f"max_safe_depth="
                        f"{_MAX_SAFE_DEPTH}, "
                        f"has_ref={has_ref}"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        if not findings and snapshot.tools:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"All tool schemas have acceptable nesting depth "
                        f"(<= {_MAX_SAFE_DEPTH}) across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
