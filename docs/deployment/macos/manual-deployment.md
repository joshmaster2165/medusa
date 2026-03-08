# macOS -- Manual Deployment

Deploy the Medusa Agent on a macOS workstation using pip and the CLI installer.

---

## Prerequisites

- **macOS 13 (Ventura) or later** (ARM64 or Intel)
- **Python 3.12+** ([Download](https://www.python.org/downloads/))
- pip or [pipx](https://pipx.pypa.io/)

---

## Step 1: Install the Package

Open Terminal:

```bash
pip install medusa-mcp
```

Verify the binary is available:

```bash
medusa-agent version
```

---

## Step 2: Install the Agent

```bash
medusa-agent install --customer-id YOUR_CUSTOMER_ID --api-key YOUR_API_KEY
```

The installer performs the following:

1. Creates `~/.medusa/` directory
2. Writes agent configuration to `~/.medusa/agent-config.yaml`
3. Initializes the SQLite database at `~/.medusa/agent.db`
4. Auto-discovers MCP clients (Claude Desktop, Cursor, Windsurf, VS Code, etc.)
5. Rewrites each client's config to route stdio servers through the gateway proxy
6. Installs a launchd Launch Agent (`com.medusa.agent`) with auto-start and crash recovery
7. Starts the daemon
8. Registers the agent with your Medusa dashboard

---

## Step 3: Verify

```bash
medusa-agent status
```

You should see the agent state as **Running** with the number of proxied servers.

---

## Service Management

The agent runs as a launchd Launch Agent with the label `com.medusa.agent`.

| Command                                      | Description                              |
| -------------------------------------------- | ---------------------------------------- |
| `medusa-agent start`                         | Start the service                        |
| `medusa-agent stop`                          | Stop the service                         |
| `medusa-agent restart`                       | Restart the service                      |
| `medusa-agent run`                           | Run in foreground (for debugging)        |
| `launchctl list \| grep com.medusa.agent`    | Query service status via macOS tools     |

### Launchd Service Details

| Property        | Value                                              |
| --------------- | -------------------------------------------------- |
| Label           | `com.medusa.agent`                                 |
| Plist Path      | `~/Library/LaunchAgents/com.medusa.agent.plist`    |
| Startup         | RunAtLoad (starts at login)                        |
| Crash Recovery  | KeepAlive (auto-restart on crash)                  |
| Throttle        | 10 seconds between restarts                        |
| Binary Path     | `medusa-agent agent-run`                           |

---

## File Locations

| File                              | Path                                   |
| --------------------------------- | -------------------------------------- |
| Agent config                      | `~/.medusa/agent-config.yaml`          |
| Gateway policy                    | `~/.medusa/gateway-policy.yaml`        |
| SQLite database                   | `~/.medusa/agent.db`                   |
| PID file                          | `~/.medusa/agent.pid`                  |
| Logs                              | `~/.medusa/logs/`                      |
| Launchd plist                     | `~/Library/LaunchAgents/com.medusa.agent.plist` |

---

## MCP Client Config Paths (macOS)

| Client          | Config File                                                                |
| --------------- | -------------------------------------------------------------------------- |
| Claude Desktop  | `~/Library/Application Support/Claude/claude_desktop_config.json`          |
| Cursor          | `~/.cursor/mcp.json`                                                       |
| Windsurf        | `~/.codeium/windsurf/mcp_config.json`                                     |
| VS Code         | `~/Library/Application Support/Code/User/settings.json`                   |
| Claude Code     | `~/.claude.json`                                                           |
| Gemini CLI      | `~/.gemini/settings.json`                                                  |
| Zed             | `~/.config/zed/settings.json`                                              |
| Continue.dev    | `~/.continue/config.yaml`                                                  |
| Amazon Q        | `~/.aws/amazonq/mcp.json`                                                  |

---

## Installer Options

| Flag              | Description                                      |
| ----------------- | ------------------------------------------------ |
| `--skip-daemon`   | Install config and patch clients, but do not start the service |
| `--skip-register` | Do not register the agent with the dashboard     |

---

## Uninstalling

```bash
medusa-agent uninstall
```

This stops the service, removes the launchd plist, restores original MCP client
configurations, and deletes all local data.

Use `--keep-data` to preserve `~/.medusa/` files.
