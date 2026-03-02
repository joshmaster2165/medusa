# Scanning

## Server Discovery

Medusa supports three methods for finding MCP servers:

### Auto-Discovery (Default)

Scans known configuration locations:

- **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- **Cursor**: `~/.cursor/mcp.json`
- **Windsurf**: `~/.windsurf/mcp.json`

```bash
medusa scan  # auto-discovers all configured servers
```

### Explicit Targets

```bash
# HTTP/SSE server
medusa scan --http http://localhost:3000/mcp

# Stdio server (local process)
medusa scan --stdio "npx my-mcp-server"

# From a specific config file
medusa scan --config-file ~/.cursor/mcp.json

# Scan only one server from config
medusa scan --server my-server-name
```

### Configuration File

Define servers in `medusa.yaml`:

```yaml
discovery:
  servers:
    - name: api-server
      transport: http
      url: http://localhost:3000/mcp
      headers:
        Authorization: "Bearer ${TOKEN}"
    - name: local-tools
      transport: stdio
      command: npx
      args: ["@myorg/mcp-tools"]
```

## Scan Modes

| Mode | Flag | Description |
|------|------|-------------|
| **Static** | *(default)* | 487 checks, fast, free |
| **Static + AI Reasoning** | `--reason` | Static checks + AI validation, attack chains, gap discovery |
| Legacy AI | `--ai` | AI-only analysis (deprecated, use `--reason`) |
| Legacy Full | `--all` | Static + legacy AI (deprecated, use `--reason`) |

### Static Scan

```bash
medusa scan
```

Runs all 487 static security checks. No API key needed.

### AI Reasoning Scan

```bash
medusa scan --reason --claude-api-key sk-ant-...
```

First runs all static checks, then sends findings + server snapshot to Claude for semantic analysis:

- **Validates** each finding (confirmed / false positive)
- **Correlates** findings into multi-step attack chains
- **Discovers** security gaps that static checks miss
- **Prioritizes** with an executive summary and remediation plan

## Filtering Checks

```bash
# By category
medusa scan --category tool_poisoning,credential_exposure

# By severity
medusa scan --severity critical

# Specific checks only
medusa scan --checks tp001,tp002,cred001

# Exclude specific checks
medusa scan --exclude-checks iv010,iv011
```

## Output Options

```bash
# Console (default) — rich terminal tables
medusa scan

# JSON — machine-readable
medusa scan -o json --output-file results.json

# HTML dashboard — interactive report
medusa scan -o html --output-file report.html

# Markdown — for documentation
medusa scan -o markdown --output-file report.md

# SARIF — for GitHub/IDE integration
medusa scan -o sarif --output-file results.sarif
```

!!! tip "Pipe Detection"
    When stdout is piped (e.g., `medusa scan | jq .`), Medusa automatically switches from console to JSON output.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings above threshold |
| `1` | Findings at or above `--fail-on` severity |
| `2` | Configuration or setup error |
| `3` | No MCP servers found |

```bash
# Fail on high or critical findings
medusa scan --fail-on high

# Fail only on critical
medusa scan --fail-on critical
```

## Compliance

```bash
# OWASP MCP Top 10 evaluation
medusa scan --compliance owasp_mcp_top10
```

Evaluates findings against the OWASP MCP Top 10 security requirements and reports compliance status per requirement.

## Concurrency

```bash
# Scan up to 8 servers in parallel
medusa scan --max-concurrency 8
```

Within each server, all checks run concurrently. The `--max-concurrency` flag controls how many servers are scanned simultaneously.
