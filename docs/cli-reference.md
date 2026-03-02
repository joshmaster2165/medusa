# CLI Reference

Complete reference for all Medusa CLI commands and options.

## Global Options

```bash
medusa [OPTIONS] COMMAND
```

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `-v, --verbose` | Increase verbosity (-v, -vv, -vvv) |
| `-q, --quiet` | Suppress output except errors |
| `--help` | Show help and exit |

---

## `medusa scan`

Scan MCP servers for security vulnerabilities.

```bash
medusa scan [OPTIONS]
```

### Server Discovery

| Option | Description |
|--------|-------------|
| `--http URL` | HTTP/SSE MCP server URL to scan |
| `--stdio CMD` | Stdio MCP server command to scan |
| `--config-file PATH` | Path to MCP client config file |
| `--scan-config PATH` | Path to medusa.yaml scan configuration |
| `--server NAME` | Scan a specific server from config |
| `--no-auto-discover` | Disable automatic server discovery |

### Output

| Option | Description |
|--------|-------------|
| `-o, --output FORMAT` | Report format: `console`, `json`, `html`, `markdown`, `sarif` |
| `--output-file PATH` | Write report to file |

### Check Filtering

| Option | Description |
|--------|-------------|
| `--category CATS` | Only run checks in these categories (comma-separated) |
| `--severity SEV` | Minimum severity to include |
| `--checks IDS` | Only run these check IDs (comma-separated) |
| `--exclude-checks IDS` | Skip these check IDs (comma-separated) |

### Scoring & Compliance

| Option | Description |
|--------|-------------|
| `--fail-on SEV` | Exit code 1 if findings at/above this severity (default: `high`) |
| `--compliance FRAMEWORK` | Evaluate a compliance framework |

### AI Reasoning

| Option | Description |
|--------|-------------|
| `--reason` | Enable AI reasoning engine |
| `--claude-api-key KEY` | Anthropic API key |
| `--ai-mode MODE` | `byok` (bring-your-own-key) or `proxied` |

### Legacy Modes

| Option | Description |
|--------|-------------|
| `--static` | Static checks only (default) |
| `--ai` | Legacy AI-only analysis (use `--reason` instead) |
| `--all` | Legacy static + AI combined (use `--reason` instead) |

### Baseline

| Option | Description |
|--------|-------------|
| `--baseline PATH` | Compare against baseline, show only new findings |
| `--generate-baseline PATH` | Save current findings as a baseline |

### Other

| Option | Description |
|--------|-------------|
| `--max-concurrency N` | Max parallel server scans (default: 4) |
| `--upload` | Upload results to Medusa dashboard |
| `--api-key KEY` | Medusa API key for upload |

---

## `medusa diff`

Compare two scan results and show changes.

```bash
medusa diff BEFORE_FILE AFTER_FILE [OPTIONS]
```

| Argument | Description |
|----------|-------------|
| `BEFORE_FILE` | Path to the older scan result (JSON) |
| `AFTER_FILE` | Path to the newer scan result (JSON) |

| Option | Description |
|--------|-------------|
| `-o, --output FORMAT` | Output format: `console`, `json` |
| `--output-file PATH` | Write diff to file |
| `--fail-on-new` | Exit code 1 if new findings detected |

---

## `medusa baseline show`

Display contents of a baseline file.

```bash
medusa baseline show BASELINE_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--suppressed-only` | Show only suppressed findings |

---

## `medusa baseline suppress`

Suppress a finding in a baseline by fingerprint.

```bash
medusa baseline suppress BASELINE_FILE FINGERPRINT --reason "text"
```

| Option | Description |
|--------|-------------|
| `--reason TEXT` | Required: reason for suppression |

---

## `medusa baseline unsuppress`

Remove suppression from a finding.

```bash
medusa baseline unsuppress BASELINE_FILE FINGERPRINT
```

---

## `medusa list-checks`

List all available security checks.

```bash
medusa list-checks [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--category CAT` | Filter by category |
| `--severity SEV` | Filter by severity |
| `--format FMT` | Output format: `table`, `json` |

---

## `medusa configure`

Set up Medusa CLI configuration.

```bash
medusa configure [OPTIONS]
```

Run without options for interactive wizard, or set values directly:

| Option | Description |
|--------|-------------|
| `--api-key KEY` | Medusa dashboard API key |
| `--dashboard-url URL` | Dashboard API URL |
| `--claude-api-key KEY` | Anthropic API key |
| `--ai-mode MODE` | `byok` or `proxied` |

---

## `medusa settings`

Display current configuration (API keys are masked).

```bash
medusa settings
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success / no findings above threshold |
| `1` | Findings at/above `--fail-on` level, or new findings with `--fail-on-new` |
| `2` | Configuration or setup error |
| `3` | No MCP servers found |
