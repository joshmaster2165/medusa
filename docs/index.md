# Medusa

**Medusa is an endpoint security agent for Model Context Protocol (MCP).**

Medusa provides continuous, real-time protection for MCP servers through a lightweight endpoint agent that monitors traffic, enforces security policies, and reports to a central dashboard. It also includes a gateway proxy for inline policy enforcement and DLP, and a comprehensive static scanner with 487 checks across 24 categories.

---

## Key Features

- **Endpoint Agent** -- persistent background daemon that auto-discovers MCP servers, installs gateway proxies, syncs policies, and uploads telemetry to your dashboard
- **MCP Gateway** -- inline proxy between MCP clients and servers that enforces security policies, performs DLP scanning, and provides real-time agent coaching
- **487 Security Checks** across 24 categories -- tool poisoning, prompt injection, credential exposure, input validation, and more
- **AI Reasoning Engine** -- validates findings, detects multi-step attack chains, identifies false positives, discovers gaps static checks miss
- **Auto-Discovery** -- automatically finds MCP servers from Claude Desktop, Cursor, and Windsurf configs
- **5 Output Formats** -- Console, JSON, HTML dashboard, Markdown, SARIF
- **OWASP MCP Top 10** compliance evaluation
- **Baseline & Diff** -- track finding changes over time, suppress accepted risks
- **CI/CD Ready** -- exit codes, SARIF output, `--fail-on` threshold, baseline comparison

## Quick Example

=== "Agent (Recommended)"

    ```bash
    # Install the agent
    pip install medusa-mcp
    medusa-agent install --customer-id YOUR_ID --api-key YOUR_KEY

    # Check status
    medusa-agent status

    # View logs
    medusa-agent logs -f
    ```

=== "Ad-Hoc Scan"

    ```bash
    # Install
    pip install medusa-mcp

    # Auto-discover and scan all MCP servers
    medusa scan

    # Scan with AI reasoning engine
    medusa scan --reason --claude-api-key sk-ant-...

    # CI/CD: fail if any high+ severity findings
    medusa scan -o sarif --output-file results.sarif --fail-on high
    ```

## How It Works

### Agent Mode (Real-Time Protection)

```
Install Agent --> Discover MCP Configs --> Insert Gateway Proxies
                                                  |
                        Dashboard <-- Telemetry <--+--> Policy Sync
                                                  |
                  MCP Client <-- Gateway Proxy --> MCP Server
                                    |
                         Policy Enforcement + DLP + Audit Log
```

1. **Install** the agent on an endpoint with your customer ID and API key
2. **Auto-discover** MCP server configurations from Claude Desktop, Cursor, and Windsurf
3. **Insert gateway proxies** between clients and servers for inline interception
4. **Enforce policies** -- block, warn, or coach on every MCP message in real time
5. **Upload telemetry** to your central dashboard for fleet-wide visibility

### Scanner Mode (Ad-Hoc Audits)

```
MCP Server --> Connect --> Snapshot --> 487 Static Checks --> Score
                                              |
                                     (optional) AI Reasoning
                                              |
                                     Validate / Correlate / Discover
                                              |
                                     Report (Console/JSON/HTML/SARIF)
```

1. **Connect** to your MCP servers (stdio or HTTP transport)
2. **Snapshot** the server's tools, resources, prompts, and capabilities
3. **Run 487 checks** across 24 security categories against the snapshot
4. **Score** each server on a 0-10 scale with A-F letter grades
5. **(Optional) AI Reasoning** -- send findings to Claude for semantic validation, attack chain detection, and gap discovery

## What's Next?

- [Installation](getting-started/installation.md) -- get Medusa up and running
- [Quick Start](getting-started/quickstart.md) -- deploy the agent or run your first scan
- [Agent Guide](guide/agent.md) -- configure and manage the endpoint agent
- [Gateway Guide](guide/gateway.md) -- understand inline policy enforcement
- [AI Reasoning Engine](guide/ai-reasoning.md) -- deep dive into the AI layer
- [CI/CD Integration](guide/ci-cd.md) -- add Medusa to your pipeline
