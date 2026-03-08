# Installation

## Requirements

- **Python 3.12+**
- pip or Poetry

---

## Install the Package

```bash
pip install medusa-mcp
```

### Install from source

```bash
git clone https://github.com/joshmaster2165/medusa.git
cd medusa
poetry install
```

---

## Install the Agent

The Medusa Agent provides continuous, real-time protection for MCP servers on
an endpoint. This is the recommended deployment for production environments.

```bash
medusa-agent install --customer-id YOUR_ID --api-key YOUR_KEY
```

This will:

- Create the agent configuration at `~/.medusa/agent-config.yaml`
- Initialize the local SQLite database for event storage
- Auto-discover MCP server configurations (Claude Desktop, Cursor, Windsurf)
- Insert gateway proxies for discovered servers
- Start the background daemon
- Register the agent with your Medusa dashboard

### Verify the agent is running

```bash
medusa-agent status
```

You should see a status table showing the agent state as **Running**, along
with the agent ID, customer ID, and any registered gateway proxies.

### Agent management

```bash
# View real-time logs
medusa-agent logs -f

# Stop/start/restart the daemon
medusa-agent stop
medusa-agent start
medusa-agent restart

# Run in foreground for debugging
medusa-agent run --debug

# View security posture and config findings
medusa-agent monitor

# Show current configuration
medusa-agent config

# Uninstall
medusa-agent uninstall
medusa-agent uninstall --keep-data
```

---

## Installer Options

| Flag              | Description                                      |
| ----------------- | ------------------------------------------------ |
| `--skip-daemon`   | Write config and patch clients but do not start the daemon. |
| `--skip-register` | Do not register with the dashboard.              |

---

## Platform Support

| Platform | Service mechanism   | Notes                                    |
| -------- | ------------------- | ---------------------------------------- |
| macOS    | launchd             | Daemon registers as a LaunchAgent.       |
| Windows  | Windows Service     | Daemon registers as a Windows Service.   |
| Linux    | Foreground mode     | Run with `medusa-agent run` or manage with systemd. |
