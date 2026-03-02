# Check System

Medusa's check system is designed for extensibility. Checks are auto-discovered at runtime and require no registration.

## Check Anatomy

Every check consists of two files:

```
checks/tool_poisoning/
├── tp001_hidden_instructions.py               # Check implementation
└── tp001_hidden_instructions.metadata.yaml    # Check metadata
```

### Metadata File

```yaml
check_id: tp001
title: Hidden instructions in tool description
category: tool_poisoning
severity: critical
description: >
  Detects hidden instructions embedded in tool descriptions that could
  manipulate LLM behavior when the tool is presented in context.
risk_explanation: >
  An attacker who controls a tool description can inject instructions
  that cause the LLM to perform unintended actions.
remediation: >
  Review and sanitize all tool descriptions. Remove any text that
  could be interpreted as instructions by an LLM.
references:
  - https://owasp.org/www-project-mcp-top-10/
owasp_mcp:
  - "MCP03:2025"
tags:
  - tool
  - injection
```

### Implementation File

```python
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import Finding, Severity, Status


class HiddenInstructionsCheck(BaseCheck):
    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        findings = []
        for tool in snapshot.tools:
            desc = tool.get("description", "")
            if self._has_hidden_instructions(desc):
                findings.append(
                    Finding(
                        check_id=self.metadata().check_id,
                        check_title=self.metadata().title,
                        status=Status.FAIL,
                        severity=self.metadata().severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool.get("name", "unknown"),
                        status_extended="Hidden instructions detected",
                        evidence=desc[:200],
                        remediation=self.metadata().remediation,
                        owasp_mcp=self.metadata().owasp_mcp,
                    )
                )
        if not findings:
            findings.append(self._pass_finding(snapshot))
        return findings
```

## Check Categories

| Category | Prefix | Count | Focus Area |
|----------|--------|-------|------------|
| Tool Poisoning | `tp` | 30 | Hidden instructions, description manipulation |
| Prompt Security | `pmt` | 20 | Prompt injection, template injection |
| Input Validation | `iv` | 40+ | Schema validation, type checking |
| Credential Exposure | `cred` | 20+ | Secrets, API keys, passwords |
| Agentic Behavior | `agent` | 25 | Agent autonomy, tool chaining |
| Authentication | `auth` | 4 | Auth mechanisms, session management |
| Privilege Scope | `priv` | 3 | Permission boundaries |
| Transport Security | `ts` | 4 | TLS, encryption |
| Data Protection | `dp` | 20+ | PII, sensitive data handling |
| Integrity | `intg` | 16+ | Server consistency, naming |
| Session Management | `sess` | — | Session handling |
| Error Handling | `err` | — | Error disclosure |
| Rate Limiting | `rl` | — | Abuse prevention |
| Audit Logging | `log` | 6+ | Logging and monitoring |
| Resource Security | `res` | — | Resource access control |
| SSRF & Network | `ssrf` | — | Network-level attacks |
| Supply Chain | `sc` | — | Dependencies, updates |
| Server Hardening | `sh` | — | Server configuration |
| Governance | `gov` | — | Policy compliance |
| Context Security | `ctx` | — | Context window attacks |
| Multi-Tenant | `mt` | — | Tenant isolation |
| Sampling Security | `samp` | — | Sampling attacks |
| Secrets Management | `sec` | — | Secret storage |
| Server Identity | `sid` | — | Server authentication |

## Auto-Discovery

The `CheckRegistry` discovers checks automatically:

1. Scans all subdirectories of `medusa.checks`
2. Uses `pkgutil.iter_modules()` to find Python modules
3. Imports each module and inspects classes
4. Finds classes that inherit from `BaseCheck` and aren't abstract
5. Instantiates and caches by `check_id`

```python
registry = CheckRegistry()
registry.discover_checks()

# Filter checks
checks = registry.get_checks(
    categories=["tool_poisoning"],
    severities=["critical", "high"],
)
```

## ServerSnapshot

The immutable data structure passed to every check:

| Field | Type | Description |
|-------|------|-------------|
| `server_name` | `str` | Server identifier |
| `transport_type` | `str` | "stdio" or "http" |
| `tools` | `list[dict]` | Tool definitions (name, description, inputSchema) |
| `resources` | `list[dict]` | Resource definitions (URI, description) |
| `prompts` | `list[dict]` | Prompt definitions (name, description, arguments) |
| `capabilities` | `dict` | Server-advertised capabilities |
| `config_raw` | `dict` | Original configuration |
| `env` | `dict` | Environment variables |
| `args` | `list[str]` | Command arguments |
| `server_info` | `dict` | Server metadata |
