# Linux -- Manual Deployment

Deploy the Medusa Agent on a Linux workstation using pip and the CLI installer.

---

## Prerequisites

- **Ubuntu 22.04+**, **Debian 12+**, or **RHEL 9+** (x86_64 or ARM64)
- **Python 3.12+** ([Download](https://www.python.org/downloads/))
- **systemd** (standard on all supported distributions)
- **Root / sudo access** (required for systemd service registration)

---

## Step 1: Install the Package

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
sudo medusa-agent install --customer-id YOUR_CUSTOMER_ID --api-key YOUR_API_KEY
```

!!! note
    `sudo` is required because the installer writes a systemd unit file to
    `/etc/systemd/system/` and runs `systemctl enable`.

The installer performs the following:

1. Creates `~/.medusa/` directory
2. Writes agent configuration to `~/.medusa/agent-config.yaml`
3. Initializes the SQLite database at `~/.medusa/agent.db`
4. Auto-discovers MCP clients (Claude Desktop, Cursor, Windsurf, VS Code, etc.)
5. Rewrites each client's config to route stdio servers through the gateway proxy
6. Writes the systemd unit file to `/etc/systemd/system/medusa-agent.service`
7. Runs `systemctl daemon-reload` and `systemctl enable medusa-agent`
8. Starts the daemon
9. Registers the agent with your Medusa dashboard

---

## Step 3: Verify

```bash
medusa-agent status
```

You should see the agent state as **Running** with the number of proxied servers.

---

## Service Management

The agent runs as a systemd service named `medusa-agent.service`.

| Command                                        | Description                              |
| ---------------------------------------------- | ---------------------------------------- |
| `sudo systemctl start medusa-agent`            | Start the service                        |
| `sudo systemctl stop medusa-agent`             | Stop the service                         |
| `sudo systemctl restart medusa-agent`          | Restart the service                      |
| `systemctl status medusa-agent`                | Check service status                     |
| `medusa-agent run`                             | Run in foreground (for debugging)        |

### Systemd Service Details

| Property        | Value                                              |
| --------------- | -------------------------------------------------- |
| Unit Name       | `medusa-agent.service`                             |
| Unit Path       | `/etc/systemd/system/medusa-agent.service`         |
| Startup         | Automatic (WantedBy=multi-user.target)             |
| Binary Path     | `medusa-agent agent-run`                           |
| Restart Policy  | Restart on failure, 10-second delay                |
| Logging         | systemd journal (`journalctl -u medusa-agent`)     |
| Environment     | `/etc/default/medusa-agent`                        |

---

## File Locations

| File                              | Path                                         |
| --------------------------------- | -------------------------------------------- |
| Agent config                      | `~/.medusa/agent-config.yaml`                |
| Gateway policy                    | `~/.medusa/gateway-policy.yaml`              |
| SQLite database                   | `~/.medusa/agent.db`                         |
| PID file                          | `~/.medusa/agent.pid`                        |
| Logs                              | `~/.medusa/logs/`                            |
| Systemd unit                      | `/etc/systemd/system/medusa-agent.service`   |
| Environment file                  | `/etc/default/medusa-agent`                  |

---

## MCP Client Config Paths (Linux)

| Client          | Config File                                                                      |
| --------------- | -------------------------------------------------------------------------------- |
| Claude Desktop  | `~/.config/Claude/claude_desktop_config.json`                                    |
| Cursor          | `~/.cursor/mcp.json`                                                              |
| Windsurf        | `~/.codeium/windsurf/mcp_config.json`                                            |
| VS Code         | `~/.config/Code/User/settings.json`                                              |
| Claude Code     | `~/.claude.json`                                                                  |
| Gemini CLI      | `~/.config/gemini/settings.json`                                                 |
| Zed             | `~/.config/zed/settings.json`                                                    |
| Continue.dev    | `~/.continue/config.yaml`                                                         |
| Amazon Q        | `~/.aws/amazonq/mcp.json`                                                         |

---

## Installer Options

| Flag              | Description                                      |
| ----------------- | ------------------------------------------------ |
| `--skip-daemon`   | Install config and patch clients, but do not start the service |
| `--skip-register` | Do not register the agent with the dashboard     |

---

## Alternative: Foreground Mode

For debugging or testing, you can run the agent in the foreground:

```bash
medusa-agent run
```

This runs the agent process directly in your terminal. Press `Ctrl+C` to stop.

---

## Environment Variables

You can set these in `/etc/default/medusa-agent` or export them before
installation:

| Variable              | Description                |
| --------------------- | -------------------------- |
| `MEDUSA_CUSTOMER_ID`  | Customer identifier        |
| `MEDUSA_API_KEY`      | API authentication key     |

---

## Uninstalling

```bash
sudo medusa-agent uninstall
```

This stops the service, removes the systemd unit, restores original MCP client
configurations, and deletes all local data.

Use `--keep-data` to preserve `~/.medusa/` files.
