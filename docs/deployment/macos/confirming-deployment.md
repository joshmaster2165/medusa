# macOS -- Confirming Deployment

After installing the Medusa Agent, use these steps to verify the deployment
is working correctly.

---

## 1. Verify the Launchd Service

```bash
launchctl list | grep com.medusa.agent
```

**Expected output:**

```
-   0   com.medusa.agent
```

The second column (`0`) indicates the last exit status. A `0` means the service
is running normally.

---

## 2. Verify Agent Status

```bash
medusa-agent status
```

This should display:

- **State:** Running
- **Agent ID:** A UUID
- **Customer ID:** Your customer ID
- **Proxies registered:** Number of discovered MCP servers

---

## 3. Verify Gateway Proxy Installation

Check that MCP client configs have been rewritten. For example, inspect
Claude Desktop's config:

```bash
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

Server entries should show `medusa-agent gateway-proxy` as the command:

```json
{
  "command": "medusa-agent",
  "args": ["gateway-proxy", "--", "npx", "-y", "..."]
}
```

---

## 4. Check Security Posture

```bash
medusa-agent monitor
```

This displays:

- **Posture:** GREEN, YELLOW, or RED
- **Gateway coverage:** Percentage of servers routed through the proxy
- **Active findings:** Security issues in MCP configs
- **Drift events:** Recent configuration changes

---

## 5. Check Logs

```bash
medusa-agent logs -n 20
```

Or view the log files directly:

```bash
cat ~/.medusa/logs/agent.log
```

---

## 6. Verify Dashboard Registration

Log in to your Medusa dashboard. The newly deployed agent should appear with:

- Hostname
- Agent ID
- Platform (darwin)
- Number of proxied servers

---

## Troubleshooting

### Service is not loaded

```bash
# Check if the plist exists
ls ~/Library/LaunchAgents/com.medusa.agent.plist

# If it exists but is not loaded, load it
medusa-agent start

# If it doesn't exist, re-install
medusa-agent install --customer-id X --api-key Y
```

### Agent status shows no proxies

The agent may not have found any MCP clients. Check:

1. Is Claude Desktop, Cursor, or another MCP client installed?
2. Does the client's config file exist? (See [Manual Deployment](manual-deployment.md) for paths)
3. Restart the agent: `medusa-agent restart`

### Gateway proxy not intercepting traffic

1. Restart the MCP client (Claude Desktop, Cursor, etc.)
2. The client reads its config at startup, so it must be restarted after the agent patches the config

### Permission errors

If the agent fails to install:

1. Ensure Python and pip have correct permissions
2. Try installing with `pip3 install --user medusa-mcp`
3. Verify the Launch Agent directory exists: `ls ~/Library/LaunchAgents/`
