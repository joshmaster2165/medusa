# Windows -- Confirming Deployment

After installing the Medusa Agent, use these steps to verify the deployment
is working correctly.

---

## 1. Verify the Windows Service

```powershell
sc.exe query MedusaAgent
```

**Expected output:**

```
SERVICE_NAME: MedusaAgent
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
        WIN32_EXIT_CODE    : 0  (0x0)
```

The `STATE` should show `RUNNING`.

---

## 2. Verify Agent Status

```powershell
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

```powershell
type "%APPDATA%\Claude\claude_desktop_config.json"
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

```powershell
medusa-agent monitor
```

This displays:

- **Posture:** GREEN, YELLOW, or RED
- **Gateway coverage:** Percentage of servers routed through the proxy
- **Active findings:** Security issues in MCP configs
- **Drift events:** Recent configuration changes

---

## 5. Check Logs

```powershell
medusa-agent logs -n 20
```

Or view the log files directly:

```powershell
type "%USERPROFILE%\.medusa\logs\agent.log"
```

---

## 6. Verify Dashboard Registration

Log in to your Medusa dashboard. The newly deployed agent should appear with:

- Hostname
- Agent ID
- Platform (windows)
- Number of proxied servers

---

## Troubleshooting

### Service is not running

```powershell
# Check if the service exists
sc.exe query MedusaAgent

# If it exists but is stopped, start it
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

The agent service requires administrator privileges for registration. If you
see permission errors:

1. Open an **Administrator PowerShell**
2. Re-run the install: `medusa-agent install --customer-id X --api-key Y`
