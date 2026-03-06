# Installation

## Requirements

- **Python 3.12+**
- pip or Poetry

---

## Agent Installation (Recommended)

The Medusa Agent provides continuous, real-time protection for MCP servers on an endpoint. This is the recommended deployment for production environments.

### 1. Install the package

```bash
pip install medusa-mcp
```

### 2. Install the agent

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

### 3. Verify the agent is running

```bash
medusa-agent status
```

You should see a status table showing the agent state as **Running**, along with the agent ID, customer ID, and any registered gateway proxies.

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

# Show current configuration
medusa-agent config

# Uninstall (keeps data by default)
medusa-agent uninstall
medusa-agent uninstall --keep-data
```

---

## Scanner-Only Installation (for CI/CD or Ad-Hoc Use)

If you only need the CLI scanner for one-off audits or CI/CD pipelines, you can install and use Medusa without the agent.

### Install from PyPI

```bash
pip install medusa-mcp
```

### Install from source

```bash
git clone https://github.com/joshmaster2165/medusa.git
cd medusa
poetry install
```

### Verify installation

```bash
medusa --version
```

You should see:

```
medusa, version 0.1.0
```

---

## Optional: AI Reasoning Engine

To use the AI reasoning engine (`--reason` flag), you need a Claude API key:

```bash
# Option 1: Environment variable
export ANTHROPIC_API_KEY=sk-ant-...

# Option 2: Pass directly
medusa scan --reason --claude-api-key sk-ant-...
```

## Optional: Dashboard Integration

To upload scan results to your Medusa dashboard:

```bash
medusa scan --upload --api-key sk_medusa_...
```
