# Architecture Overview

Medusa is built as a modular Python application with clear separation of concerns. The architecture spans three layers: an **endpoint agent** for continuous protection, a **gateway proxy** for inline policy enforcement, and a **scan engine** for static security analysis.

## High-Level Architecture

```
+---------------------------------------------------------------+
|                   Agent Layer (Daemon)                         |
|  Config Watch . Telemetry . Policy Sync . Health Monitor      |
+---------------------------------------------------------------+
|                   Gateway Layer (Proxy)                        |
|  Stdio Interception . Policy Engine . DLP . Audit Log         |
+---------------------------------------------------------------+
|                   CLI Layer (Click)                            |
|  medusa-agent: install/start/stop/status/logs/config          |
|  medusa: scan . quickscan . diff . baseline . list-checks     |
+---------------------------------------------------------------+
|                   Scan Engine                                  |
|  Orchestration . Concurrency . Progress . Scoring             |
+--------------+--------------+-----------------------------+
|  Connectors  |   Checks     |  AI Reasoning Engine        |
|  stdio/http  |   487 static |  Validate . Correlate       |
|  discovery   |   24 cats    |  Discover . Prioritize      |
+--------------+--------------+-----------------------------+
|                   Core Models                                 |
|  Finding . ScanResult . ServerSnapshot . Severity             |
+---------------------------------------------------------------+
|                   Reporters                                    |
|  Console . JSON . HTML . Markdown . SARIF                     |
+---------------------------------------------------------------+
|                   Utilities                                    |
|  Heuristics . Pattern Matching . Text Analysis                |
+---------------------------------------------------------------+
```

## Module Structure

```
src/medusa/
+-- agent/               # Endpoint agent (daemon)
|   +-- daemon.py        # AgentDaemon orchestrator (asyncio event loop)
|   +-- installer.py     # Install/uninstall logic
|   +-- config_watcher.py # Auto-discover new MCP configs and proxy them
|   +-- telemetry.py     # Batch-upload events to dashboard
|   +-- policy_sync.py   # Fetch policies from dashboard
|   +-- health.py        # Monitor proxy process liveness
|   +-- store.py         # SQLite event/state store
|   +-- models.py        # AgentConfig, AgentState, paths
|   +-- platform/        # OS-specific daemon management
|       +-- common.py    # PID file, signal handlers, platform detection
|       +-- darwin.py    # macOS launchd integration
|       +-- windows.py   # Windows Service integration
+-- gateway/             # MCP gateway proxy
|   +-- proxy.py         # Stdio proxy (sits between client and server)
|   +-- interceptor.py   # JSON-RPC message parsing, classification
|   +-- policy.py        # PolicyEngine, Verdict (allow/block/warn/coach)
|   +-- dlp.py           # Data loss prevention scanning
|   +-- config_rewriter.py # Rewrite MCP client configs to insert proxy
+-- cli/                 # Command-line interfaces
|   +-- main.py          # medusa CLI (scan, diff, baseline, etc.)
|   +-- agent_cli.py     # medusa-agent CLI (install, start, status, etc.)
|   +-- banner.py        # ASCII art banner
|   +-- config.py        # User config (~/.medusa/config.yaml)
+-- core/                # Core engine
|   +-- scanner.py       # ScanEngine orchestrator
|   +-- check.py         # BaseCheck abstract class, ServerSnapshot
|   +-- models.py        # Finding, ScanResult, Severity, Status
|   +-- registry.py      # CheckRegistry (auto-discovery)
|   +-- scoring.py       # Score calculation (0-10, A-F grades)
|   +-- baseline.py      # Baseline management
|   +-- diff.py          # Scan result diffing
|   +-- exceptions.py    # Custom exception hierarchy
+-- checks/              # 487 security checks
|   +-- tool_poisoning/       # 30 checks
|   +-- prompt_security/      # 20 checks
|   +-- input_validation/     # 40+ checks
|   +-- credential_exposure/  # 20+ checks
|   +-- agentic_behavior/     # 25 checks
|   +-- toxic_flows/          # Cross-tool attack flow checks
|   +-- ... (24 categories)
+-- connectors/          # MCP server connections
|   +-- base.py          # BaseConnector interface
|   +-- stdio.py         # Local process (stdio transport)
|   +-- http.py          # Remote server (HTTP/SSE transport)
|   +-- config_discovery.py   # Auto-discover from client configs
+-- ai/                  # AI integration
|   +-- client.py        # Claude API client (BYOK + proxy)
|   +-- reasoning/       # AI Reasoning Engine
|   |   +-- engine.py        # Orchestrator
|   |   +-- prompts.py       # System/user prompt templates
|   |   +-- chunker.py       # Token budget management
|   |   +-- models.py        # ReasoningResult, AttackChain, etc.
|   |   +-- response_parser.py  # Tolerant JSON parser
|   +-- credits.py       # Credit management
|   +-- throttle.py      # Rate limiting
+-- reporters/           # Output generators
|   +-- base.py          # BaseReporter interface
|   +-- console_reporter.py
|   +-- json_reporter.py
|   +-- html_reporter.py
|   +-- markdown_reporter.py
|   +-- sarif_reporter.py
+-- compliance/          # Compliance frameworks
|   +-- framework.py     # Framework evaluation
|   +-- owasp_mcp_top10.yaml
+-- utils/               # Shared utilities
    +-- heuristics.py          # Semantic pattern analysis
    +-- pattern_matching.py    # Regex detection
    +-- text_analysis.py       # Unicode, encoding analysis
    +-- patterns/              # Pattern libraries
        +-- identity.py        # Identity/auth patterns
        +-- schema.py          # Schema validation patterns
        +-- context_patterns.py  # Context security patterns
        +-- resource_patterns.py # Resource access patterns
```

## Data Flow

### Agent Mode (Real-Time)

```
MCP Client <--> Gateway Proxy <--> MCP Server
                     |
              Policy Engine (allow/block/warn/coach)
                     |
              DLP Scanner (sensitive data detection)
                     |
              Audit Log --> SQLite Store --> Telemetry Upload --> Dashboard
```

The gateway proxy intercepts every JSON-RPC message between client and server. Each message is classified (tool call, tool result, resource read, etc.) and evaluated against the active policy. The policy engine returns a verdict: allow, block, warn, or coach. Blocked messages receive an error response. Coached messages include inline guidance. All events are logged to the local SQLite store and batch-uploaded to the dashboard.

### Scanner Mode (Ad-Hoc)

#### 1. Connection Phase

```
CLI --> Connector --> MCP Server --> ServerSnapshot (frozen dataclass)
```

The `ServerSnapshot` captures:
- Tools (names, descriptions, input schemas)
- Resources (URIs, descriptions)
- Prompts (names, descriptions, arguments)
- Capabilities (server-advertised features)
- Config raw (original configuration)

#### 2. Check Execution Phase

```
ServerSnapshot --> CheckRegistry --> [Check1, Check2, ...] --> [Finding, Finding, ...]
```

All checks run concurrently against the immutable snapshot. Each check returns a list of `Finding` objects.

#### 3. AI Reasoning Phase (Optional)

```
FAIL Findings + Snapshot --> Token Chunker --> Claude API --> ReasoningResult
```

The reasoning engine sends 1-3 API calls per server, chunked by token budget.

#### 4. Scoring Phase

```
Findings --> Severity Weights --> Server Score (0-10) --> Grade (A-F)
```

#### 5. Reporting Phase

```
ScanResult --> Reporter --> Console / JSON / HTML / Markdown / SARIF
```

## Key Design Decisions

### Agent as Persistent Daemon

The agent runs as an asyncio event loop with concurrent subtasks for config watching, telemetry, policy sync, and health monitoring. On macOS it integrates with launchd; on Windows it runs as a Windows Service. This ensures the agent survives reboots and runs without user intervention.

### Gateway Proxy Interception

Rather than modifying MCP clients or servers, the gateway rewrites client configuration files to point at the proxy process. The proxy spawns the real server as a child process and relays stdio traffic, intercepting every message. This approach requires zero changes to existing MCP tooling.

### Immutable ServerSnapshot

The snapshot is a frozen dataclass. All checks operate on the same read-only data, enabling safe concurrent execution.

### Auto-Discovery Check Registry

Checks are discovered at runtime via `pkgutil.iter_modules()`. No registration required -- drop a `.py` + `.metadata.yaml` pair into a category directory and it is automatically included.

### Two-Phase AI Architecture

Static checks run first (free, fast). AI reasoning is optional and post-processes the results. This means:
- Free scans are still comprehensive
- AI costs are predictable (1-2 calls, not 487)
- AI has full context (all findings + snapshot)

### Tolerant Parsing

The AI response parser uses defensive parsing -- malformed fields are skipped rather than raising exceptions. Partial results are always returned.

### Local-First Telemetry

Events are stored in a local SQLite database first, then batch-uploaded to the dashboard. This ensures no data loss during network outages and keeps the gateway proxy fast (no synchronous network calls in the hot path).
