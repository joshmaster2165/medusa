# Quick Start

Get your first security scan running in under 2 minutes.

## 1. Install Medusa

```bash
pip install medusa-mcp
```

## 2. Scan Your MCP Servers

### Auto-discover (recommended)

Medusa automatically discovers MCP servers from Claude Desktop, Cursor, and Windsurf:

```bash
medusa scan
```

### Scan a specific server

```bash
# HTTP server
medusa scan --http http://localhost:3000/mcp

# Stdio server
medusa scan --stdio "npx my-mcp-server"

# From a config file
medusa scan --config-file ~/.cursor/mcp.json
```

## 3. Read the Results

Medusa outputs a rich console report with:

- **Grade**: A-F letter grade (A = secure, F = critical issues)
- **Score**: 0-10 numeric score
- **Findings**: Organized by severity (critical → info)
- **Per-server breakdown**: Individual scores for each server

## 4. Enable AI Reasoning (Optional)

Add the `--reason` flag for AI-powered analysis:

```bash
medusa scan --reason --claude-api-key sk-ant-...
```

This adds:

- **Finding validation** — confirms or marks as false positive
- **Attack chain detection** — finds multi-step exploitation paths
- **Gap discovery** — finds issues static checks missed
- **Executive summary** — prioritized remediation guidance

## 5. Generate Reports

```bash
# HTML dashboard
medusa scan -o html --output-file report.html

# JSON for automation
medusa scan -o json --output-file results.json

# SARIF for GitHub Code Scanning
medusa scan -o sarif --output-file results.sarif

# Markdown for documentation
medusa scan -o markdown --output-file report.md
```

## 6. CI/CD Integration

```bash
# Exit code 1 if any high+ severity findings
medusa scan -o json --fail-on high

# Generate baseline, then only alert on NEW findings
medusa scan --generate-baseline .medusa-baseline.json
medusa scan --baseline .medusa-baseline.json --fail-on high
```

## What's Next?

- [Configuration](configuration.md) — customize scans with `medusa.yaml`
- [AI Reasoning Engine](../guide/ai-reasoning.md) — understand the AI layer
- [Baselines & Diff](../guide/baselines.md) — track changes over time
