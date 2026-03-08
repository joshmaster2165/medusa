# Architecture Overview

Medusa is built as a modular Python application with clear separation of
concerns. The architecture spans two layers: an **endpoint agent** for
continuous protection and a **gateway proxy** for inline policy enforcement.

## High-Level Architecture

```
+---------------------------------------------------------------+
|                   Agent Layer (Daemon)                         |
|  Config Watch . Telemetry . Policy Sync . Health . Config Mon |
+---------------------------------------------------------------+
|                   Gateway Layer (Proxy)                        |
|  Stdio Interception . Policy Engine . DLP . Audit Log         |
+---------------------------------------------------------------+
|                   CLI Layer (Click)                            |
|  medusa-agent: install/start/stop/status/logs/config/monitor  |
+---------------------------------------------------------------+
```

## Module Structure

```
src/medusa/
+-- agent/               # Endpoint agent (daemon)
|   +-- daemon.py        # AgentDaemon orchestrator (asyncio event loop)
|   +-- installer.py     # Install/uninstall logic
|   +-- config_watcher.py # Auto-discover new MCP configs and proxy them
|   +-- config_monitor.py # Drift detection, security checks, posture scoring
|   +-- telemetry.py     # Batch-upload events to dashboard
|   +-- policy_sync.py   # Fetch policies from dashboard
|   +-- health.py        # Monitor proxy process liveness
|   +-- store.py         # SQLite event/state store (WAL mode)
|   +-- models.py        # AgentConfig, AgentState, TelemetryEvent
|   +-- platform/        # OS-specific daemon management
|       +-- common.py    # PID file, signal handlers, platform detection
|       +-- darwin.py    # macOS launchd integration
|       +-- windows.py   # Windows Service integration
+-- gateway/             # MCP gateway proxy
|   +-- proxy.py         # Stdio proxy (sits between client and server)
|   +-- interceptor.py   # JSON-RPC message parsing, classification
|   +-- policy.py        # PolicyEngine, Verdict (allow/block/coach)
|   +-- dlp.py           # Data loss prevention scanning
|   +-- config_rewriter.py # Rewrite MCP client configs to insert proxy
+-- connectors/          # MCP client discovery
|   +-- mcp_clients.py   # Config paths, platform detection, parsing
+-- cli/                 # Command-line interface
|   +-- agent_cli.py     # medusa-agent CLI (install, start, status, monitor, etc.)
+-- utils/               # Shared utilities
    +-- patterns/        # Pattern libraries
        +-- credentials.py # Secret detection patterns (used by DLP)
```

## Data Flow

### Agent Mode (Real-Time)

```
MCP Client <--> Gateway Proxy <--> MCP Server
                     |
              Policy Engine (allow/block/coach)
                     |
              DLP Scanner (secrets, PII detection)
                     |
              Audit Log --> SQLite Store --> Telemetry Upload --> Dashboard
```

The gateway proxy intercepts every JSON-RPC message between client and server.
Each message is classified (tool call, tool result, resource read, etc.) and
evaluated against the active policy. The policy engine returns a verdict:
allow, block, or coach. Blocked messages receive an error response. Coached
messages include inline guidance. All events are logged to the local SQLite
store and batch-uploaded to the dashboard.

### Config Monitoring

```
MCP Client Configs --> Config Monitor --> Drift Events + Security Findings
                                                |
                                         Posture Score (GREEN/YELLOW/RED)
                                                |
                                         SQLite Store --> Dashboard
```

The config monitor runs every 5 minutes and performs:

1. **Drift detection** -- compares current configs against a stored baseline
2. **Security checks** -- 10 rules (CFG001--CFG010) for dangerous patterns
3. **Posture scoring** -- calculates overall security posture

## Key Design Decisions

### Agent as Persistent Daemon

The agent runs as an asyncio event loop with concurrent subtasks for config
watching, telemetry, policy sync, health monitoring, and config monitoring.
On macOS it integrates with launchd; on Windows it runs as a Windows Service.
This ensures the agent survives reboots and runs without user intervention.

### Gateway Proxy Interception

Rather than modifying MCP clients or servers, the gateway rewrites client
configuration files to point at the proxy process. The proxy spawns the real
server as a child process and relays stdio traffic, intercepting every message.
This approach requires zero changes to existing MCP tooling.

### Local-First Telemetry

Events are stored in a local SQLite database first, then batch-uploaded to
the dashboard. This ensures no data loss during network outages and keeps the
gateway proxy fast (no synchronous network calls in the hot path).

### SQLite WAL for IPC

The SQLite database uses Write-Ahead Logging (WAL) mode, allowing the daemon
and multiple gateway proxy processes to read and write concurrently. Proxy
processes write events; the daemon reads and uploads them.
