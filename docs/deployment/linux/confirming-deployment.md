# Linux -- Confirming Deployment

After installing the Medusa Agent, use these steps to verify the deployment
is working correctly.

---

## 1. Verify the Systemd Service

```bash
systemctl status medusa-agent
```

**Expected output:**

```
● medusa-agent.service - Medusa Security Agent for MCP
     Loaded: loaded (/etc/systemd/system/medusa-agent.service; enabled)
     Active: active (running) since ...
   Main PID: 12345 (medusa-agent)
```

The `Active` line should show `active (running)`.

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
cat ~/.config/Claude/claude_desktop_config.json
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

View recent journal logs:

```bash
journalctl -u medusa-agent -n 20
```

Follow the log stream in real time:

```bash
journalctl -u medusa-agent -f
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
- Platform (linux)
- Number of proxied servers

---

## Troubleshooting

### Service is not running

```bash
# Check if the unit file exists
ls /etc/systemd/system/medusa-agent.service

# Check service status for errors
systemctl status medusa-agent

# If the unit exists but the service is stopped, start it
sudo systemctl start medusa-agent

# If the unit doesn't exist, re-install
sudo medusa-agent install --customer-id X --api-key Y
```

### Agent status shows no proxies

The agent may not have found any MCP clients. Check:

1. Is Claude Desktop, Cursor, or another MCP client installed?
2. Does the client's config file exist? (See [Manual Deployment](manual-deployment.md) for paths)
3. Restart the agent: `sudo systemctl restart medusa-agent`

### Gateway proxy not intercepting traffic

1. Restart the MCP client (Claude Desktop, Cursor, etc.)
2. The client reads its config at startup, so it must be restarted after the agent patches the config

### Permission errors

The agent service requires root/sudo privileges for systemd registration. If you
see permission errors:

1. Re-run the install with sudo: `sudo medusa-agent install --customer-id X --api-key Y`
2. Check the environment file: `cat /etc/default/medusa-agent`

### Journal shows repeated restarts

If the service restarts repeatedly, check for errors:

```bash
journalctl -u medusa-agent --no-pager -n 50
```

Common causes:

- Missing Python dependencies (`pip install medusa-mcp`)
- Invalid agent config (`~/.medusa/agent-config.yaml`)
- Network connectivity issues to `*.supabase.co`
