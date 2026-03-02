# OWASP MCP Top 10

Medusa evaluates MCP servers against the **OWASP MCP Top 10 (2025)** security framework. This maps security findings to standardized risk categories specific to the Model Context Protocol.

## Usage

```bash
medusa scan --compliance owasp_mcp_top10
```

## The OWASP MCP Top 10

| Code | Category | Description |
|------|----------|-------------|
| **MCP01:2025** | Prompt Injection | Tool descriptions or resources containing instructions that manipulate LLM behavior |
| **MCP02:2025** | Tool Misuse | Tools with overly broad capabilities or insufficient input validation |
| **MCP03:2025** | Tool Poisoning | Malicious content hidden in tool definitions (hidden text, unicode manipulation) |
| **MCP04:2025** | Privilege Escalation | Tools or resources that enable unauthorized access to elevated privileges |
| **MCP05:2025** | Data Exfiltration | Capabilities that allow extraction of sensitive data to unauthorized destinations |
| **MCP06:2025** | Indirect Prompt Injection | External content (resources, prompts) that inject malicious instructions |
| **MCP07:2025** | Unauthorized Access | Missing authentication, authorization, or access controls |
| **MCP08:2025** | Config Exposure | Sensitive configuration, credentials, or secrets exposed in server state |
| **MCP09:2025** | Logging Gaps | Insufficient audit logging for security-relevant operations |
| **MCP10:2025** | Supply Chain | Risks from third-party dependencies, unverified tool sources, or update mechanisms |

## Check Category Mapping

Medusa's 24 check categories map to the OWASP MCP Top 10:

| Medusa Category | OWASP MCP Codes |
|----------------|-----------------|
| Tool Poisoning | MCP03 |
| Prompt Security | MCP01, MCP06 |
| Input Validation | MCP02 |
| Credential Exposure | MCP08 |
| Authentication | MCP07 |
| Privilege Scope | MCP04 |
| Data Protection | MCP05 |
| Transport Security | MCP07 |
| Supply Chain | MCP10 |
| Audit Logging | MCP09 |
| Agentic Behavior | MCP01, MCP02 |

## Compliance Report

When you run with `--compliance owasp_mcp_top10`, the report includes:

- **Pass/Fail** status for each of the 10 requirements
- **Finding count** per requirement
- **Evidence** — which specific findings map to each requirement

### Console Output

```
OWASP MCP Top 10 Compliance
┌──────────────┬────────┬──────────┐
│ Requirement  │ Status │ Findings │
├──────────────┼────────┼──────────┤
│ MCP01:2025   │ FAIL   │ 3        │
│ MCP02:2025   │ FAIL   │ 5        │
│ MCP03:2025   │ PASS   │ 0        │
│ ...          │ ...    │ ...      │
└──────────────┴────────┴──────────┘
```

### JSON Output

```json
{
  "compliance_results": {
    "owasp_mcp_top10": {
      "MCP01:2025": {
        "status": "fail",
        "finding_count": 3,
        "findings": [...]
      }
    }
  }
}
```
