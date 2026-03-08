# Gateway Proxy

The Gateway Proxy is a transparent stdio proxy that sits between MCP clients
and MCP servers. It intercepts every JSON-RPC message flowing in both
directions, evaluates it against a configurable policy, and emits an audit
record for each decision.

---

## Deployment

### Option 1: Agent Install (Recommended)

The easiest way to deploy the gateway is through the Medusa Agent. The agent
auto-discovers MCP clients, inserts the gateway proxy into their configs, and
manages everything automatically.

#### Prerequisites

- **Python 3.12+**
- An active Medusa dashboard account (customer ID and API key)

#### Step-by-step

```bash
# 1. Install the package
pip install medusa-mcp

# 2. Install the agent (discovers clients, inserts proxies, starts daemon)
medusa-agent install --customer-id YOUR_ID --api-key YOUR_KEY

# 3. Verify the gateway is active
medusa-agent status
```

The installer performs the following:

1. Creates `~/.medusa/` and writes `agent-config.yaml`
2. Initializes the SQLite database (`agent.db`) in WAL mode
3. Auto-discovers MCP clients (Claude Desktop, Cursor, Windsurf)
4. Rewrites each client's config to route stdio servers through the gateway proxy
5. Registers a platform-native daemon (launchd on macOS, Windows Service on Windows)
6. Starts the daemon

After installation, every stdio MCP server on the endpoint is automatically
proxied. The daemon continuously watches for new servers and proxies them too.

#### Verify gateway coverage

```bash
# Check how many servers are proxied
medusa-agent status

# View security posture and gateway coverage percentage
medusa-agent monitor

# Watch proxy activity in real time
medusa-agent logs -f
```

### Option 2: Manual Standalone Install

If you want to use the gateway proxy without the full agent daemon (for quick
experiments or CI pipelines), you can invoke it directly:

```bash
medusa-agent gateway-proxy -- npx -y @modelcontextprotocol/server-everything
```

In this mode the proxy still reads policy from `~/.medusa/gateway-policy.yaml`
(if the file exists) and writes audit records to `~/.medusa/agent.db`. However
there is no automatic client discovery, no telemetry upload, and no policy
sync. You are responsible for creating the policy file and managing the
database yourself.

#### Manual config rewrite

To manually insert the proxy into a client config, change the server entry:

**Before:**
```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-everything"]
    }
  }
}
```

**After:**
```json
{
  "mcpServers": {
    "my-server": {
      "command": "medusa-agent",
      "args": [
        "gateway-proxy",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-everything"
      ]
    }
  }
}
```

!!! tip
    Manual mode is useful for quick experiments or CI pipelines where you want
    policy enforcement on a single server without installing the daemon.

### Option 3: Custom policy file

You can specify an explicit policy file when running the proxy manually:

```bash
medusa-agent gateway-proxy --policy-file /path/to/policy.yaml -- npx my-server
```

---

## How it works

When the [Medusa Agent](agent.md) installs into an MCP client, it rewrites
the client configuration so that the server command is launched through the
proxy. The original command:

```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-everything"]
}
```

becomes:

```json
{
  "command": "medusa-agent",
  "args": [
    "gateway-proxy",
    "--",
    "npx", "-y", "@modelcontextprotocol/server-everything"
  ]
}
```

The proxy starts the original server as a child process and relays
stdin/stdout traffic between the client and the server. Every JSON-RPC message
is decoded, evaluated against the active policy, and then either forwarded,
blocked, or annotated before continuing.

### Message classification

The proxy classifies every JSON-RPC message before evaluation:

| Message Type       | Description                              |
| ------------------ | ---------------------------------------- |
| `INITIALIZE`       | MCP handshake                            |
| `TOOL_CALL`        | Client requests a tool invocation        |
| `TOOL_LIST`        | Client lists available tools             |
| `RESOURCE_READ`    | Client reads a resource                  |
| `RESOURCE_LIST`    | Client lists available resources         |
| `PROMPT_GET`       | Client retrieves a prompt                |
| `PROMPT_LIST`      | Client lists available prompts           |
| `NOTIFICATION`     | Async notification (either direction)    |
| `RESPONSE`         | Server response to a request             |
| `ERROR`            | JSON-RPC error                           |

Direction is also tracked: `CLIENT_TO_SERVER` (request) vs `SERVER_TO_CLIENT`
(response).

---

## Policy engine

Each intercepted message is evaluated against the policy rules. The engine
returns one of three verdicts:

| Verdict   | Behaviour                                                        |
| --------- | ---------------------------------------------------------------- |
| **ALLOW** | The message is passed through to the other side unchanged.       |
| **BLOCK** | The message is rejected. The proxy returns a JSON-RPC error to the sender. |
| **COACH** | The message is blocked, but a suggestion is included in the error data for the LLM to read. |

### Evaluation order

The policy engine evaluates rules in this order:

1. **Server blocklist/allowlist** -- is this server permitted?
2. **Tool blocklist** -- exact tool name match
3. **Tool pattern matching** -- regex against tool names
4. **Rate limiting** -- calls per minute threshold
5. **DLP scanning** -- secrets, PII, source code detection

The first rule that triggers determines the verdict.

---

## Policy configuration

The policy file lives at:

```
~/.medusa/gateway-policy.yaml
```

When the Medusa Agent is running, this file is automatically kept in sync with
the dashboard (see [Agent -- Policy sync](agent.md#policy-sync)). You can also
edit it by hand for local testing.

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
    - approved-server-2
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
| `blocked_tool_patterns`          | list of string | Regular expressions matched against tool names. |
| `blocked_servers`                | list of string | Server names whose traffic is blocked entirely. |
| `allowed_servers`                | list of string | Server names explicitly allowed. If set, all others are blocked. |
| `max_calls_per_minute`           | integer        | Rate limit for tool-call messages per proxy instance. |
| `data_protection.block_secrets`  | boolean        | Block messages that contain detected secrets. |
| `data_protection.block_pii`     | boolean        | Block messages that contain detected PII. |
| `data_protection.scan_responses` | boolean        | Apply DLP scanning to server responses (not just client requests). |
| `data_protection.scan_code`      | boolean        | Apply DLP scanning to code blocks in messages. |
| `coaching.enabled`               | boolean        | Enable coaching verdicts instead of silent allow. |

---

## DLP scanning

When data-protection rules are enabled, the proxy scans message payloads for
sensitive content before forwarding them.

### Secrets detection

The scanner looks for common secret patterns including:

- API keys and tokens (AWS, GitHub, Stripe, generic bearer tokens)
- Passwords and credentials in plaintext
- Private keys and certificates

### PII detection

The scanner looks for personally identifiable information including:

- Email addresses
- Social Security Numbers (SSN)
- Credit card numbers
- Phone numbers
- IPv4 addresses

!!! note
    DLP scanning adds a small amount of latency to each message. If you do not
    need it, set `block_secrets` and `block_pii` to `false` and
    `scan_responses` to `false` to bypass the scanner entirely.

---

## Audit logging

Every message processed by the proxy is logged to the local SQLite database at
`~/.medusa/agent.db`. Each record includes:

- Timestamp
- Direction (client-to-server or server-to-client)
- JSON-RPC method
- Tool name (if applicable)
- Server name
- Verdict (ALLOW, BLOCK, or COACH)
- Rule that triggered (if any)
- DLP match details (if any)

When the Medusa Agent daemon is running, these records are batched and uploaded
to the Supabase dashboard for centralised visibility.

!!! info
    Audit records are written regardless of the verdict. Even ALLOW messages
    are logged so that you have a complete trace of all MCP traffic.

---

## Supported clients

The gateway auto-discovers and proxies configs from these MCP clients:

| Client          | Config path (macOS)                                    |
| --------------- | ------------------------------------------------------ |
| Claude Desktop  | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Cursor          | `~/.cursor/mcp.json`                                   |
| Windsurf        | `~/.codeium/windsurf/mcp_config.json`                  |

!!! note
    Only **stdio** servers (entries with a `command` field) are proxied. HTTP
    servers are left unchanged since they communicate over the network rather
    than stdin/stdout.

---

## Troubleshooting

### Gateway proxy is not intercepting traffic

1. Check that the agent is running: `medusa-agent status`
2. Verify the client config was rewritten: look for `medusa-agent gateway-proxy` in the config file
3. Restart the MCP client (Claude Desktop, Cursor, etc.) to pick up config changes

### Policy changes are not taking effect

- The proxy loads policy at startup. Restart the MCP client to pick up new policy.
- If using the agent daemon, policy is synced from the dashboard every 5 minutes.
- Check the policy file exists: `cat ~/.medusa/gateway-policy.yaml`

### Proxy crashes or server fails to start

```bash
# Run the proxy in the foreground to see error output
medusa-agent gateway-proxy -- <your-server-command>
```

### View audit events

```bash
# Check the local database
sqlite3 ~/.medusa/agent.db "SELECT * FROM events ORDER BY timestamp DESC LIMIT 10;"
```

### Check security posture

```bash
# View posture score, gateway coverage, and active findings
medusa-agent monitor
```
