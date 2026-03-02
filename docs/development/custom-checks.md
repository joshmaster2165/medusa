# Writing Custom Checks

Medusa's check system is fully extensible. You can add custom checks by creating two files in a category directory.

## Step 1: Create the Metadata File

Create a `.metadata.yaml` sidecar file describing your check:

```yaml
# checks/tool_poisoning/tp_custom001_my_check.metadata.yaml
check_id: tp_custom001
title: Custom tool description check
category: tool_poisoning
severity: high
description: >
  Detects a specific pattern in tool descriptions that indicates
  a potential security issue.
risk_explanation: >
  If this pattern is present, an attacker could exploit it to
  manipulate LLM behavior.
remediation: >
  Remove the problematic pattern from the tool description.
references:
  - https://example.com/security-advisory
owasp_mcp:
  - "MCP03:2025"
tags:
  - tool
  - custom
```

## Step 2: Implement the Check

Create a Python file with a class that inherits from `BaseCheck`:

```python
# checks/tool_poisoning/tp_custom001_my_check.py
"""Custom check for specific tool description patterns."""

from __future__ import annotations

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import Finding, Status


class MyCustomCheck(BaseCheck):
    """Detect specific patterns in tool descriptions."""

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        findings: list[Finding] = []
        meta = self.metadata()

        for tool in snapshot.tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "")

            if self._is_problematic(desc):
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=name,
                        status_extended=(
                            f"Tool '{name}' contains a problematic pattern "
                            f"in its description."
                        ),
                        evidence=desc[:200],
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # If no issues found, return a PASS finding
        if not findings:
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
                    status_extended="No problematic patterns found.",
                    remediation=meta.remediation,
                )
            )

        return findings

    def _is_problematic(self, text: str) -> bool:
        """Check if text contains the problematic pattern."""
        # Your detection logic here
        keywords = ["dangerous_pattern", "exploit_me"]
        return any(kw in text.lower() for kw in keywords)
```

## Step 3: Drop It In

Place both files in the appropriate category directory:

```
src/medusa/checks/tool_poisoning/
├── tp_custom001_my_check.py
└── tp_custom001_my_check.metadata.yaml
```

That's it! The `CheckRegistry` will auto-discover your check on the next scan.

## Check ID Convention

| Category | Prefix | Example |
|----------|--------|---------|
| Tool Poisoning | `tp` | `tp001` |
| Prompt Security | `pmt` | `pmt001` |
| Input Validation | `iv` | `iv001` |
| Credential Exposure | `cred` | `cred001` |
| Authentication | `auth` | `auth001` |
| Custom checks | Use `custom_` prefix | `custom_001` |

## ServerSnapshot Reference

Your check receives a `ServerSnapshot` with these fields:

```python
@dataclass(frozen=True)
class ServerSnapshot:
    server_name: str        # Server identifier
    transport_type: str     # "stdio" or "http"
    tools: list[dict]       # [{name, description, inputSchema}, ...]
    resources: list[dict]   # [{uri, name, description}, ...]
    prompts: list[dict]     # [{name, description, arguments}, ...]
    capabilities: dict      # Server capabilities
    config_raw: dict        # Original config
    env: dict              # Environment variables
    args: list[str]        # Command arguments
    server_info: dict      # Server metadata
```

## Testing Your Check

```python
# tests/unit/test_checks/test_my_custom_check.py
import pytest
from medusa.core.check import ServerSnapshot

from medusa.checks.tool_poisoning.tp_custom001_my_check import MyCustomCheck


@pytest.fixture
def snapshot():
    return ServerSnapshot(
        server_name="test",
        transport_type="stdio",
        tools=[
            {"name": "bad_tool", "description": "Contains dangerous_pattern here"},
            {"name": "good_tool", "description": "A perfectly safe tool"},
        ],
        resources=[],
        prompts=[],
        capabilities={},
        config_raw={},
        env={},
        args=[],
        server_info={},
    )


async def test_detects_problematic_tool(snapshot):
    check = MyCustomCheck()
    findings = await check.execute(snapshot)
    fails = [f for f in findings if f.status.value == "fail"]
    assert len(fails) == 1
    assert fails[0].resource_name == "bad_tool"
```

## Using Utility Functions

Medusa provides shared utility functions for common patterns:

```python
from medusa.utils.text_analysis import (
    find_hidden_tags,
    find_injection_phrases,
    find_suspicious_unicode,
)
from medusa.utils.heuristics import evaluate_pattern_strength
from medusa.utils.pattern_matching import SECRET_PATTERNS
```

## Best Practices

1. **Always return findings** — PASS or FAIL, never an empty list
2. **Include evidence** — truncate to ~200 chars for readability
3. **Use metadata severity** — don't hardcode severity in the check
4. **Test both positive and negative** cases
5. **Keep checks focused** — one concern per check
6. **Use the `owasp_mcp` field** to map to the Top 10
