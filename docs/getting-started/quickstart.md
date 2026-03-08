# Quick Start

Get Medusa protecting your MCP servers in under 5 minutes.

---

## 1. Install Medusa

```bash
pip install medusa-mcp
```

## 2. Install the Agent

```bash
medusa-agent install --customer-id YOUR_ID --api-key YOUR_KEY
```

The installer will auto-discover MCP servers from Claude Desktop, Cursor, and
Windsurf, insert gateway proxies, and start the background daemon.

## 3. Verify It Is Running

```bash
medusa-agent status
```

You should see:

- **State**: Running
- **Proxies registered**: the number of MCP servers discovered and proxied

## 4. Check Security Posture

```bash
medusa-agent monitor
```

This shows:

- **Posture score**: GREEN, YELLOW, or RED
- **Gateway coverage**: percentage of servers routed through the proxy
- **Active findings**: security issues found in MCP configs (CFG001--CFG010)
- **Drift events**: recent changes to MCP server configurations

## 5. View Activity

```bash
# Follow logs in real time
medusa-agent logs -f
```

The agent is now actively monitoring all MCP traffic on this endpoint. Gateway
proxies enforce policies, perform DLP scanning, and log audit events to the
local store. Telemetry is uploaded to your dashboard automatically.

## 6. Check the Dashboard

Log in to your Medusa dashboard to see the agent, its proxied servers, and any
policy violations or security events.

---

## What's Next?

- [Agent Guide](../guide/agent.md) -- configure policies, manage proxies, view config monitoring
- [Gateway Guide](../guide/gateway.md) -- understand inline policy enforcement, deployment options, and DLP
- [Configuration](configuration.md) -- customize agent and gateway policy settings
