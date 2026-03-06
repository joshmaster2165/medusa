# Gateway Proxy

The Gateway Proxy is a transparent stdio proxy that sits between MCP clients
and MCP servers. It intercepts every JSON-RPC message flowing in both
directions, evaluates it against a configurable policy, and emits an audit
record for each decision.

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
  "command": "medusa",
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

## Policy engine

Each intercepted message is evaluated against the policy rules. The engine
returns one of three verdicts:

| Verdict   | Behaviour                                                        |
| --------- | ---------------------------------------------------------------- |
| **ALLOW** | The message is passed through to the other side unchanged.       |
| **BLOCK** | The message is rejected. The proxy returns a JSON-RPC error to the sender. |
| **COACH** | The message is passed through, but a warning is logged and optionally surfaced to the user. |

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
| `max_calls_per_minute`           | integer        | Rate limit for tool-call messages per proxy instance. |
| `data_protection.block_secrets`  | boolean        | Block messages that contain detected secrets. |
| `data_protection.block_pii`     | boolean        | Block messages that contain detected PII. |
| `data_protection.scan_responses` | boolean        | Apply DLP scanning to server responses (not just client requests). |
| `data_protection.scan_code`      | boolean        | Apply DLP scanning to code blocks in messages. |
| `coaching.enabled`               | boolean        | Enable coaching verdicts instead of silent allow. |

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
- Phone numbers

!!! note
    DLP scanning adds a small amount of latency to each message. If you do not
    need it, set `block_secrets` and `block_pii` to `false` and
    `scan_responses` to `false` to bypass the scanner entirely.

## Audit logging

Every message processed by the proxy is logged to the local SQLite database at
`~/.medusa/agent.db`. Each record includes:

- Timestamp
- Direction (client-to-server or server-to-client)
- JSON-RPC method
- Verdict (ALLOW, BLOCK, or COACH)
- DLP match details (if any)

When the Medusa Agent daemon is running, these records are batched and uploaded
to the Supabase dashboard for centralised visibility.

!!! info
    Audit records are written regardless of the verdict. Even ALLOW messages
    are logged so that you have a complete trace of all MCP traffic.

## Manual install (without the agent)

If you want to use the gateway proxy without the full agent daemon, you can
invoke it directly:

```bash
medusa gateway-proxy -- npx -y @modelcontextprotocol/server-everything
```

In this mode the proxy still reads policy from `~/.medusa/gateway-policy.yaml`
(if the file exists) and writes audit records to `~/.medusa/agent.db`. However
there is no automatic client discovery, no telemetry upload, and no policy
sync. You are responsible for creating the policy file and managing the
database yourself.

!!! tip
    Manual mode is useful for quick experiments or CI pipelines where you want
    policy enforcement on a single server without installing the daemon.
