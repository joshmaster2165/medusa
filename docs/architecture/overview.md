# Architecture Overview

Medusa is built as a modular Python application with clear separation of concerns.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLI Layer (Click)                     │
│  scan · list-checks · diff · baseline · configure        │
├─────────────────────────────────────────────────────────┤
│                    Scan Engine                            │
│  Orchestration · Concurrency · Progress · Scoring        │
├──────────────┬──────────────┬───────────────────────────┤
│  Connectors  │   Checks     │  AI Reasoning Engine      │
│  stdio/http  │   487 static │  Validate · Correlate     │
│  discovery   │   24 cats    │  Discover · Prioritize    │
├──────────────┴──────────────┴───────────────────────────┤
│                    Core Models                            │
│  Finding · ScanResult · ServerSnapshot · Severity        │
├─────────────────────────────────────────────────────────┤
│                    Reporters                              │
│  Console · JSON · HTML · Markdown · SARIF                │
├─────────────────────────────────────────────────────────┤
│                    Utilities                              │
│  Heuristics · Pattern Matching · Text Analysis           │
└─────────────────────────────────────────────────────────┘
```

## Module Structure

```
src/medusa/
├── cli/              # Command-line interface
│   ├── main.py       # Click commands (scan, diff, baseline, etc.)
│   ├── banner.py     # ASCII art banner
│   └── config.py     # User config (~/.medusa/config.yaml)
├── core/             # Core engine
│   ├── scanner.py    # ScanEngine orchestrator
│   ├── check.py      # BaseCheck abstract class, ServerSnapshot
│   ├── models.py     # Finding, ScanResult, Severity, Status
│   ├── registry.py   # CheckRegistry (auto-discovery)
│   ├── scoring.py    # Score calculation (0-10, A-F grades)
│   ├── baseline.py   # Baseline management
│   ├── diff.py       # Scan result diffing
│   └── exceptions.py # Custom exception hierarchy
├── checks/           # 487 security checks
│   ├── tool_poisoning/       # 30 checks
│   ├── prompt_security/      # 20 checks
│   ├── input_validation/     # 40+ checks
│   ├── credential_exposure/  # 20+ checks
│   ├── agentic_behavior/     # 25 checks
│   └── ... (24 categories)
├── connectors/       # MCP server connections
│   ├── base.py       # BaseConnector interface
│   ├── stdio.py      # Local process (stdio transport)
│   ├── http.py       # Remote server (HTTP/SSE transport)
│   └── config_discovery.py   # Auto-discover from configs
├── ai/               # AI integration
│   ├── client.py     # Claude API client (BYOK + proxy)
│   ├── reasoning/    # AI Reasoning Engine
│   │   ├── engine.py     # Orchestrator
│   │   ├── prompts.py    # System/user prompt templates
│   │   ├── chunker.py    # Token budget management
│   │   ├── models.py     # ReasoningResult, AttackChain, etc.
│   │   └── response_parser.py  # Tolerant JSON parser
│   ├── credits.py    # Credit management
│   └── throttle.py   # Rate limiting
├── reporters/        # Output generators
│   ├── base.py       # BaseReporter interface
│   ├── console_reporter.py
│   ├── json_reporter.py
│   ├── html_reporter.py
│   ├── markdown_reporter.py
│   └── sarif_reporter.py
├── compliance/       # Compliance frameworks
│   ├── framework.py  # Framework evaluation
│   └── owasp_mcp_top10.yaml
└── utils/            # Shared utilities
    ├── heuristics.py       # Semantic pattern analysis
    ├── pattern_matching.py # Regex detection
    └── text_analysis.py    # Unicode, encoding analysis
```

## Data Flow

### 1. Connection Phase

```
CLI → Connector → MCP Server → ServerSnapshot (frozen dataclass)
```

The `ServerSnapshot` captures:
- Tools (names, descriptions, input schemas)
- Resources (URIs, descriptions)
- Prompts (names, descriptions, arguments)
- Capabilities (server-advertised features)
- Config raw (original configuration)

### 2. Check Execution Phase

```
ServerSnapshot → CheckRegistry → [Check1, Check2, ...] → [Finding, Finding, ...]
```

All checks run concurrently against the immutable snapshot. Each check returns a list of `Finding` objects.

### 3. AI Reasoning Phase (Optional)

```
FAIL Findings + Snapshot → Token Chunker → Claude API → ReasoningResult
```

The reasoning engine sends 1-3 API calls per server, chunked by token budget.

### 4. Scoring Phase

```
Findings → Severity Weights → Server Score (0-10) → Grade (A-F)
```

### 5. Reporting Phase

```
ScanResult → Reporter → Console / JSON / HTML / Markdown / SARIF
```

## Key Design Decisions

### Immutable ServerSnapshot

The snapshot is a frozen dataclass. All checks operate on the same read-only data, enabling safe concurrent execution.

### Auto-Discovery Check Registry

Checks are discovered at runtime via `pkgutil.iter_modules()`. No registration required — drop a `.py` + `.metadata.yaml` pair into a category directory and it's automatically included.

### Two-Phase AI Architecture

Static checks run first (free, fast). AI reasoning is optional and post-processes the results. This means:
- Free scans are still comprehensive
- AI costs are predictable (1-2 calls, not 487)
- AI has full context (all findings + snapshot)

### Tolerant Parsing

The AI response parser uses defensive parsing — malformed fields are skipped rather than raising exceptions. Partial results are always returned.
