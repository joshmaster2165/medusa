# Medusa

**Medusa is an endpoint security agent for Model Context Protocol (MCP).**

Medusa provides continuous, real-time protection for MCP servers through a
lightweight endpoint agent that monitors traffic, enforces security policies,
detects configuration drift, and reports to a central dashboard.

---

## Key Features

- **Endpoint Agent** -- persistent background daemon that auto-discovers MCP servers, installs gateway proxies, syncs policies, and uploads telemetry to your dashboard
- **MCP Gateway** -- inline proxy between MCP clients and servers that enforces security policies, performs DLP scanning, and provides real-time agent coaching
- **Config Monitoring** -- drift detection, 10 security rules for MCP configs, and posture scoring (GREEN/YELLOW/RED)
- **Auto-Discovery** -- automatically finds MCP servers from Claude Desktop, Cursor, and Windsurf configs
- **DLP Scanning** -- detects secrets, PII, and sensitive data in MCP traffic before it leaves the endpoint
- **Dashboard Telemetry** -- batches and streams events to a cloud dashboard for fleet-wide visibility

## Quick Example

```bash
# Install the agent
pip install medusa-mcp
medusa-agent install --customer-id YOUR_ID --api-key YOUR_KEY

# Check status
medusa-agent status

# View security posture
medusa-agent monitor

# View logs
medusa-agent logs -f
```

## How It Works

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
5. **Monitor configs** -- detect drift, run security checks, calculate posture scores
6. **Upload telemetry** to your central dashboard for fleet-wide visibility

## What's Next?

- [Installation](getting-started/installation.md) -- get Medusa up and running
- [Quick Start](getting-started/quickstart.md) -- deploy the agent in under 5 minutes
- [Agent Guide](guide/agent.md) -- configure and manage the endpoint agent
- [Gateway Guide](guide/gateway.md) -- understand inline policy enforcement and deployment
