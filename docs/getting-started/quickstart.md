# Quick Start

Get Medusa protecting your MCP servers in under 5 minutes.

---

## Agent Quick Start (Recommended)

The agent provides continuous, real-time protection by sitting between MCP clients and servers.

### 1. Install Medusa

```bash
pip install medusa-mcp
```

### 2. Install the Agent

```bash
medusa-agent install --customer-id YOUR_ID --api-key YOUR_KEY
```

The installer will auto-discover MCP servers from Claude Desktop, Cursor, and Windsurf, insert gateway proxies, and start the background daemon.

### 3. Verify It Is Running

```bash
medusa-agent status
```

You should see:

- **State**: Running
- **Proxies registered**: the number of MCP servers discovered and proxied

### 4. View Activity

```bash
# Follow logs in real time
medusa-agent logs -f
```

The agent is now actively monitoring all MCP traffic on this endpoint. Gateway proxies enforce policies, perform DLP scanning, and log audit events to the local store. Telemetry is uploaded to your dashboard automatically.

### 5. Check the Dashboard

Log in to your Medusa dashboard to see the agent, its proxied servers, and any policy violations or security events.

---

## Ad-Hoc Scanning (CLI)

For one-off security audits, CI/CD pipelines, or environments where you do not need a persistent agent, use the scanner directly.

### 1. Install Medusa

```bash
pip install medusa-mcp
```

### 2. Scan Your MCP Servers

#### Auto-discover (recommended)

Medusa automatically discovers MCP servers from Claude Desktop, Cursor, and Windsurf:

```bash
medusa scan
```

#### Scan a specific server

```bash
# HTTP server
medusa scan --http http://localhost:3000/mcp

# Stdio server
medusa scan --stdio "npx my-mcp-server"

# From a config file
medusa scan --config-file ~/.cursor/mcp.json
```

### 3. Read the Results

Medusa outputs a rich console report with:

- **Grade**: A-F letter grade (A = secure, F = critical issues)
- **Score**: 0-10 numeric score
- **Findings**: Organized by severity (critical to info)
- **Per-server breakdown**: Individual scores for each server

### 4. Enable AI Reasoning (Optional)

Add the `--reason` flag for AI-powered analysis:

```bash
medusa scan --reason --claude-api-key sk-ant-...
```

This adds:

- **Finding validation** -- confirms or marks as false positive
- **Attack chain detection** -- finds multi-step exploitation paths
- **Gap discovery** -- finds issues static checks missed
- **Executive summary** -- prioritized remediation guidance

### 5. Generate Reports

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

### 6. CI/CD Integration

```bash
# Exit code 1 if any high+ severity findings
medusa scan -o json --fail-on high

# Generate baseline, then only alert on NEW findings
medusa scan --generate-baseline .medusa-baseline.json
medusa scan --baseline .medusa-baseline.json --fail-on high
```

---

## What's Next?

- [Agent Guide](../guide/agent.md) -- configure policies, manage proxies, fleet deployment
- [Gateway Guide](../guide/gateway.md) -- understand inline policy enforcement and DLP
- [Configuration](configuration.md) -- customize scans with `medusa.yaml`
- [AI Reasoning Engine](../guide/ai-reasoning.md) -- understand the AI layer
- [Baselines & Diff](../guide/baselines.md) -- track changes over time
