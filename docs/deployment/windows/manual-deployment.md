# Windows -- Manual Deployment

Deploy the Medusa Agent on a Windows workstation using pip and the CLI installer.

---

## Prerequisites

- **Windows 10 or later** (x86_64)
- **Python 3.12+** ([Download](https://www.python.org/downloads/))
- **Administrator privileges** (required for Windows Service registration)

---

## Step 1: Install the Package

Open an **Administrator PowerShell** or Command Prompt:

```powershell
pip install medusa-mcp
```

Verify the binary is available:

```powershell
medusa-agent version
```

---

## Step 2: Install the Agent

```powershell
medusa-agent install --customer-id YOUR_CUSTOMER_ID --api-key YOUR_API_KEY
```

The installer performs the following:

1. Creates `%USERPROFILE%\.medusa\` directory
2. Writes agent configuration to `%USERPROFILE%\.medusa\agent-config.yaml`
3. Initializes the SQLite database at `%USERPROFILE%\.medusa\agent.db`
4. Auto-discovers MCP clients (Claude Desktop, Cursor, Windsurf, VS Code, etc.)
5. Rewrites each client's config to route stdio servers through the gateway proxy
6. Registers `MedusaAgent` as a Windows Service with auto-start and failure restart
7. Starts the daemon
8. Registers the agent with your Medusa dashboard

---

## Step 3: Verify

```powershell
medusa-agent status
```

You should see the agent state as **Running** with the number of proxied servers.

---

## Service Management

The agent runs as a Windows Service named `MedusaAgent`.

| Command                    | Description                              |
| -------------------------- | ---------------------------------------- |
| `medusa-agent start`       | Start the service                        |
| `medusa-agent stop`        | Stop the service                         |
| `medusa-agent restart`     | Restart the service                      |
| `medusa-agent run`         | Run in foreground (for debugging)        |
| `sc.exe query MedusaAgent` | Query service status via Windows tools   |

### Windows Service Details

| Property       | Value                                              |
| -------------- | -------------------------------------------------- |
| Service Name   | `MedusaAgent`                                      |
| Display Name   | `Medusa Security Agent`                            |
| Startup Type   | Automatic                                          |
| Binary Path    | `medusa-agent.exe agent-run`                       |
| Failure Policy | Restart after 5s, 10s, 30s; reset counter after 24h |

---

## File Locations

| File                              | Path                                         |
| --------------------------------- | -------------------------------------------- |
| Agent config                      | `%USERPROFILE%\.medusa\agent-config.yaml`    |
| Gateway policy                    | `%USERPROFILE%\.medusa\gateway-policy.yaml`  |
| SQLite database                   | `%USERPROFILE%\.medusa\agent.db`             |
| PID file                          | `%USERPROFILE%\.medusa\agent.pid`            |
| Logs                              | `%USERPROFILE%\.medusa\logs\`                |

---

## MCP Client Config Paths (Windows)

| Client         | Config File                                                    |
| -------------- | -------------------------------------------------------------- |
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json`                  |
| Cursor         | `%APPDATA%\.cursor\mcp.json`                                   |
| Windsurf       | `%APPDATA%\Codeium\Windsurf\mcp_config.json`                  |
| VS Code        | `%APPDATA%\Code\User\settings.json`                            |
| Claude Code    | `%USERPROFILE%\.claude.json`                                    |

---

## Installer Options

| Flag              | Description                                      |
| ----------------- | ------------------------------------------------ |
| `--skip-daemon`   | Install config and patch clients, but do not start the service |
| `--skip-register` | Do not register the agent with the dashboard     |

---

## Uninstalling

```powershell
medusa-agent uninstall
```

This stops the service, removes the `MedusaAgent` Windows Service, restores
original MCP client configurations, and deletes all local data.

Use `--keep-data` to preserve `%USERPROFILE%\.medusa\` files.
