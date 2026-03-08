# Configuration

Medusa uses two configuration files:

1. **Agent config** (`~/.medusa/agent-config.yaml`) -- agent identity and daemon settings
2. **Gateway policy** (`~/.medusa/gateway-policy.yaml`) -- security rules for the gateway proxy

---

## Agent Configuration

The agent configuration is created during installation and lives at:

```
~/.medusa/agent-config.yaml
```

### View current config

```bash
medusa-agent config
```

### Configuration fields

| Field                              | Type    | Default | Description                             |
| ---------------------------------- | ------- | ------- | --------------------------------------- |
| `customer_id`                      | string  | --      | Your Medusa dashboard customer ID       |
| `api_key`                          | string  | --      | API key for dashboard authentication    |
| `agent_id`                         | string  | auto    | Unique agent identifier (auto-generated)|
| `telemetry_interval_seconds`       | integer | 60      | How often to upload telemetry (seconds) |
| `policy_sync_interval_seconds`     | integer | 300     | How often to fetch policy (seconds)     |
| `config_watcher_interval_seconds`  | integer | 30      | How often to check for new MCP servers  |
| `health_check_interval_seconds`    | integer | 60      | How often to verify proxy liveness      |
| `config_monitor_interval_seconds`  | integer | 300     | How often to run config security checks |
| `config_monitor_enabled`           | boolean | true    | Enable/disable config monitoring        |

!!! note
    Editing the config file while the daemon is running requires a restart
    (`medusa-agent restart`) for changes to take effect.

---

## Gateway Policy

The gateway policy controls how the proxy evaluates MCP traffic. It lives at:

```
~/.medusa/gateway-policy.yaml
```

When the agent daemon is running, this file is automatically synced from the
Medusa dashboard every 5 minutes. You can also edit it by hand for local
testing.

### Example policy

```yaml
policies:
  blocked_tools:
    - dangerous_tool
    - delete_everything
  blocked_tool_patterns:
    - ".*admin.*"
  blocked_servers:
    - untrusted-server
  allowed_servers:
    - approved-server-1
  max_calls_per_minute: 60
  data_protection:
    block_secrets: true
    block_pii: false
    scan_responses: true
    scan_code: false
  coaching:
    enabled: true
```

### Policy fields

| Field                            | Type           | Description |
| -------------------------------- | -------------- | ----------- |
| `blocked_tools`                  | list of string | Tool names that are unconditionally blocked. |
| `blocked_tool_patterns`          | list of string | Regex patterns matched against tool names. |
| `blocked_servers`                | list of string | Server names whose traffic is blocked entirely. |
| `allowed_servers`                | list of string | If set, only these servers are allowed. |
| `max_calls_per_minute`           | integer        | Rate limit for tool calls per proxy instance. |
| `data_protection.block_secrets`  | boolean        | Block messages containing detected secrets. |
| `data_protection.block_pii`     | boolean        | Block messages containing detected PII. |
| `data_protection.scan_responses` | boolean        | Apply DLP to server responses too. |
| `data_protection.scan_code`      | boolean        | Apply DLP to code blocks. |
| `coaching.enabled`               | boolean        | Return coaching suggestions in blocked responses. |

See the [Gateway Guide](../guide/gateway.md) for detailed information on
policy enforcement and DLP scanning.

---

## Data Storage

All runtime data is stored at:

```
~/.medusa/
  agent-config.yaml       # Agent configuration
  gateway-policy.yaml     # Gateway policy (synced from dashboard)
  agent.db                # SQLite database (events, state, proxy registry)
  agent.pid               # PID file for daemon management
```

The SQLite database uses WAL (Write-Ahead Logging) mode for safe concurrent
access between the daemon and gateway proxy processes.
