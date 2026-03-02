# AI Reasoning Engine

The AI Reasoning Engine is Medusa's most powerful feature — it post-processes static scan findings using Claude to provide semantic analysis that pattern-matching alone cannot achieve.

## Architecture

```
Static Scan (487 checks)
        ↓
   FAIL findings + ServerSnapshot
        ↓
   Token Budget Chunking (if needed)
        ↓
   Claude API (1-2 calls per server)
        ↓
   Parse + Merge Reasoning Results
        ↓
   Enriched Report
```

### Two-Phase Design

**Phase 1: Static Checks** (free, fast)

All 487 checks run against the server snapshot using regex, heuristics, and structural analysis. This produces PASS/FAIL findings.

**Phase 2: AI Reasoning** (requires Claude API key)

Only the FAIL findings (plus the full server snapshot for context) are sent to Claude. The AI performs four tasks:

1. **Validate** — confirm or reject each finding
2. **Correlate** — connect findings into attack chains
3. **Discover** — find gaps that static checks missed
4. **Prioritize** — produce an executive summary and remediation plan

## Usage

```bash
# Using environment variable
export ANTHROPIC_API_KEY=sk-ant-...
medusa scan --reason

# Using flag
medusa scan --reason --claude-api-key sk-ant-...

# Using saved config
medusa configure --claude-api-key sk-ant-...
medusa scan --reason
```

## What the AI Produces

### Finding Annotations

Each FAIL finding gets annotated with:

| Field | Description |
|-------|-------------|
| `confidence` | `confirmed`, `likely`, `uncertain`, `likely_false_positive`, `false_positive` |
| `confidence_score` | 0.0 (certainly FP) to 1.0 (certainly real) |
| `reasoning` | 1-2 sentence explanation |
| `false_positive_reason` | Why the AI thinks it's a false positive |
| `exploitability_note` | How the issue could be exploited in practice |
| `adjusted_severity` | If the actual severity differs from the static check's rating |

### False Positive Detection

The AI identifies false positives using 7 reason codes:

| Code | Meaning |
|------|---------|
| `documentation_context` | Finding appears in documentation text |
| `example_code` | Sample/example code, not production |
| `security_measure` | The pattern IS a security control |
| `negation_context` | Context negates the finding ("don't do X") |
| `insufficient_evidence` | Not enough data to confirm |
| `semantic_misunderstanding` | Static check misread the intent |
| `benign_pattern` | Looks suspicious but is harmless |

### Attack Chains

The AI identifies multi-step exploitation sequences:

```json
{
  "chain_id": "chain_001",
  "title": "Credential Theft via Tool Poisoning",
  "severity": "critical",
  "finding_check_ids": ["tp002", "cred001", "priv005"],
  "attack_narrative": "Step 1: Attacker poisons tool description...",
  "impact": "Full database credential exfiltration",
  "owasp_mcp": ["MCP03:2025", "MCP05:2025"]
}
```

### Gap Findings

New security issues discovered by the AI that static checks missed:

```json
{
  "title": "Unrestricted glob pattern in file_access tool",
  "severity": "high",
  "evidence": "inputSchema allows any string for 'path' parameter",
  "reasoning": "Static checks cannot assess absence of path restrictions"
}
```

Gap findings are converted into standard `Finding` objects with the check ID prefix `ai_gap_`.

### Executive Summary

A prioritized remediation plan:

```
Executive Summary:
Server 'my-server' has 3 critical findings forming an exploitable
attack chain. Tool poisoning combined with unrestricted file access
creates a high-risk path to data exfiltration.

Top Priorities:
1. Remove hidden instructions from execute_command tool description
2. Add path allowlist to file_access tool inputSchema
3. Rotate database credentials exposed in db_query configuration
```

## Token Budget Management

The reasoning engine uses smart chunking to stay within Claude's context window:

- Estimates ~4 characters per token
- Reserves tokens for system prompt and output
- Groups findings by category prefix for coherent analysis
- Sends 1-3 API calls per server (depending on finding count)
- If everything fits in one call, sends ALL findings (including PASS) for full context

## Cost

- **Static scan**: Free (no API calls)
- **AI reasoning**: 1-2 Claude API calls per server
- Uses `claude-sonnet-4-20250514` by default
- Typical cost: ~$0.01-0.05 per server scan

## OWASP MCP Top 10 References

The AI maps findings to OWASP MCP codes:

| Code | Category |
|------|----------|
| MCP01 | Prompt Injection |
| MCP02 | Tool Misuse |
| MCP03 | Tool Poisoning |
| MCP04 | Privilege Escalation |
| MCP05 | Data Exfiltration |
| MCP06 | Indirect Prompt Injection |
| MCP07 | Unauthorized Access |
| MCP08 | Config Exposure |
| MCP09 | Logging Gaps |
| MCP10 | Supply Chain |
