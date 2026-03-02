# Medusa

**Security scanner for Model Context Protocol (MCP) servers.**

Medusa performs automated security audits of MCP servers using **487 static checks** across **24 categories**, with an optional **AI reasoning engine** that validates findings, discovers attack chains, and identifies false positives.

---

## Key Features

- **487 Security Checks** across 24 categories — tool poisoning, prompt injection, credential exposure, input validation, and more
- **AI Reasoning Engine** — validates findings, detects multi-step attack chains, identifies false positives, discovers gaps static checks miss
- **Auto-Discovery** — automatically finds MCP servers from Claude Desktop, Cursor, and Windsurf configs
- **5 Output Formats** — Console, JSON, HTML dashboard, Markdown, SARIF
- **OWASP MCP Top 10** compliance evaluation
- **Baseline & Diff** — track finding changes over time, suppress accepted risks
- **CI/CD Ready** — exit codes, SARIF output, `--fail-on` threshold, baseline comparison

## Quick Example

```bash
# Install
pip install medusa-mcp

# Auto-discover and scan all MCP servers
medusa scan

# Scan with AI reasoning engine
medusa scan --reason --claude-api-key sk-ant-...

# CI/CD: fail if any high+ severity findings
medusa scan -o sarif --output-file results.sarif --fail-on high

# Track changes with baselines
medusa scan --generate-baseline .medusa-baseline.json
medusa scan --baseline .medusa-baseline.json  # only new findings

# Compare two scans
medusa diff before.json after.json --fail-on-new
```

## How It Works

```
MCP Server → Connect → Snapshot → 487 Static Checks → Score
                                       ↓
                              (optional) AI Reasoning
                                       ↓
                              Validate · Correlate · Discover
                                       ↓
                              Report (Console/JSON/HTML/SARIF)
```

1. **Connect** to your MCP servers (stdio or HTTP transport)
2. **Snapshot** the server's tools, resources, prompts, and capabilities
3. **Run 487 checks** across 24 security categories against the snapshot
4. **Score** each server on a 0-10 scale with A-F letter grades
5. **(Optional) AI Reasoning** — send findings to Claude for semantic validation, attack chain detection, and gap discovery

## What's Next?

- [Installation](getting-started/installation.md) — get Medusa up and running
- [Quick Start](getting-started/quickstart.md) — your first scan in 2 minutes
- [AI Reasoning Engine](guide/ai-reasoning.md) — deep dive into the AI layer
- [CI/CD Integration](guide/ci-cd.md) — add Medusa to your pipeline
