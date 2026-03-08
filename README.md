<p align="center">
  <img src="docs/logo.svg" alt="Medusa Logo" width="300">
</p>
<p align="center">
  <strong>Endpoint security agent for MCP</strong>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python 3.12+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-green.svg" alt="License: Apache 2.0"></a>
</p>

<p align="center">
  Medusa is an open-source endpoint security agent that auto-discovers <a href="https://modelcontextprotocol.io">Model Context Protocol (MCP)</a> clients, installs a gateway proxy to intercept all MCP traffic, and enforces security policies in real time. It delivers ALLOW, BLOCK, and COACH verdicts on every JSON-RPC message, scans for secrets and PII via built-in DLP, monitors configuration drift, and streams telemetry to a cloud dashboard.
</p>

---

## Features

### Endpoint Agent

- **Background daemon** -- runs as a launchd service on macOS or a Windows Service, starting automatically at boot.
- **Auto-discovery** -- detects MCP clients such as Claude Desktop, Cursor, Windsurf, and custom configurations without manual setup.
- **Gateway proxy** -- transparently intercepts all JSON-RPC traffic between MCP clients and servers.
- **Real-time policy enforcement** -- evaluates every request and response against configurable rules, returning ALLOW, BLOCK, or COACH verdicts.
- **DLP scanning** -- inspects payloads for secrets, PII, and source code patterns before they leave the endpoint.
- **Cloud dashboard telemetry** -- batches and streams events to a Supabase-backed dashboard for centralized visibility.
- **Policy sync** -- pulls updated rules from the dashboard so fleet-wide policy changes propagate automatically.
- **Config monitoring** -- detects configuration drift, runs 10 security rules (CFG001--CFG010) against MCP configs, and calculates posture scores (GREEN/YELLOW/RED).

---

## Quick Start

Install the agent as a background daemon that continuously monitors and protects all MCP traffic on the endpoint.

```bash
pip install medusa-mcp
medusa-agent install --customer-id <CUSTOMER_ID> --api-key <API_KEY>
```

The installer registers a launchd service (macOS) or Windows Service, auto-discovers running MCP clients, and begins intercepting traffic immediately.

### Agent Commands

| Command | Description |
|---------|-------------|
| `medusa-agent install` | Register the daemon and configure the gateway proxy |
| `medusa-agent uninstall` | Remove the daemon, proxy config, and local state |
| `medusa-agent start` | Start the background service |
| `medusa-agent stop` | Stop the background service |
| `medusa-agent restart` | Restart the background service |
| `medusa-agent run` | Run in the foreground (useful for debugging) |
| `medusa-agent status` | Show daemon health, connected clients, and policy version |
| `medusa-agent logs` | Tail the agent log output |
| `medusa-agent config` | Display the active configuration |
| `medusa-agent monitor` | Show security posture, gateway coverage, and findings |
| `medusa-agent version` | Print the installed version |

---

## Architecture

```
+---------------------------------------------------------------+
|  Endpoint                                                       |
|                                                                 |
|  +---------------+    +-------------------------------------+  |
|  | Agent Daemon  |--->| Config Watcher                       |  |
|  | (launchd /    |    |  - discovers MCP clients              |  |
|  |  Win Service) |    |  - auto-proxies their configs         |  |
|  +-------+-------+    +-------------------------------------+  |
|          |                                                      |
|          v                                                      |
|  +----------------------------------------------------------+  |
|  | Gateway Proxy                                             |  |
|  |  MCP Client <--JSON-RPC--> Proxy <--JSON-RPC--> MCP Server| |
|  |                              |                            |  |
|  |                     +--------+--------+                   |  |
|  |                     |  Policy Engine  |                   |  |
|  |                     |  ALLOW / BLOCK  |                   |  |
|  |                     |  / COACH        |                   |  |
|  |                     +--------+--------+                   |  |
|  |                              |                            |  |
|  |                     +--------+--------+                   |  |
|  |                     |  DLP Scanner    |                   |  |
|  |                     |  secrets, PII   |                   |  |
|  |                     +-----------------+                   |  |
|  +----------------------------------------------------------+  |
|          |                                                      |
|          v                                                      |
|  +---------------+         +---------------+                    |
|  | Telemetry     |-------->| Supabase      |                    |
|  | Manager       | batched | Dashboard     |                    |
|  +---------------+ events  +-------+-------+                    |
|                                     |                            |
|  +---------------+                  |                            |
|  | Policy Sync  |<-----------------+                            |
|  |  fetches rules, writes local YAML                            |
|  +---------------+                                               |
|                                                                  |
|  +---------------+                                               |
|  | Config Monitor|                                               |
|  |  drift, security checks, posture scoring                     |
|  +---------------+                                               |
+------------------------------------------------------------------+
```

**Agent Daemon** -- manages lifecycle, watches for new MCP client configurations, and injects the gateway proxy into each client's config.

**Gateway Proxy** -- sits between every MCP client and server. Each JSON-RPC message passes through the policy engine (ALLOW / BLOCK / COACH) and the DLP scanner before being forwarded.

**Telemetry Manager** -- collects verdicts, DLP hits, and connection metadata, batches them, and ships them to the Supabase cloud dashboard.

**Policy Sync** -- periodically fetches the latest policy rules from the dashboard and writes them to local YAML, ensuring fleet-wide consistency.

**Config Monitor** -- detects configuration drift, runs security checks against MCP configs, and calculates an overall posture score.

---

## Gateway Policy

Create a policy file at `~/.medusa/gateway-policy.yaml` to control how the gateway proxy evaluates MCP traffic. When the agent daemon is running, this file is automatically synced from the dashboard.

```yaml
policies:
  blocked_tools:
    - dangerous_tool
  blocked_tool_patterns:
    - ".*admin.*"
  blocked_servers:
    - untrusted-server
  max_calls_per_minute: 60
  data_protection:
    block_secrets: true
    block_pii: false
    scan_responses: true
  coaching:
    enabled: true
```

---

## Development

```bash
git clone https://github.com/joshmaster2165/medusa.git
cd medusa
poetry install
poetry run pytest tests/unit/ --tb=short -q
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on running the test suite and submitting pull requests.

---

## Issues

Found a bug or have a feature request? [Open an issue](https://github.com/joshmaster2165/medusa/issues).

## License

Apache 2.0. See [LICENSE](LICENSE) for details.
