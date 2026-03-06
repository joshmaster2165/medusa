# CLI Reference

Complete reference for all Medusa CLI commands and options.

---

## `medusa-agent` Commands

The `medusa-agent` CLI manages the endpoint security agent. All commands share a global `--debug` flag to enable debug-level logging.

```bash
medusa-agent [--debug] COMMAND
```

### `medusa-agent install`

Install the Medusa Agent on this machine.

```bash
medusa-agent install --customer-id ID --api-key KEY [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--customer-id ID` | **Required.** Your Medusa customer ID |
| `--api-key KEY` | **Required.** Your Medusa API key |
| `--skip-daemon` | Do not start the background daemon after install |
| `--skip-register` | Do not register the agent with the dashboard |

### `medusa-agent uninstall`

Uninstall the Medusa Agent from this machine.

```bash
medusa-agent uninstall [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--keep-data` | Keep agent data (database, config) after uninstall |

### `medusa-agent start`

Start the agent daemon via the platform service (launchd on macOS, Windows Service on Windows).

```bash
medusa-agent start
```

### `medusa-agent stop`

Stop the running agent daemon.

```bash
medusa-agent stop
```

### `medusa-agent restart`

Stop and restart the agent daemon.

```bash
medusa-agent restart
```

### `medusa-agent run`

Run the agent in foreground mode. Useful for debugging. Press Ctrl+C to stop.

```bash
medusa-agent run [--debug]
```

| Option | Description |
|--------|-------------|
| `--debug` | Enable debug-level logging output |

### `medusa-agent status`

Show agent status, health information, and gateway proxy details.

```bash
medusa-agent status
```

Displays: agent state, PID, agent ID, customer ID, platform, hostname, config/database paths, event counts, and a table of registered gateway proxies with their liveness state.

### `medusa-agent logs`

Show agent log output.

```bash
medusa-agent logs [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-n, --lines N` | Number of log lines to show (default: 50) |
| `-f, --follow` | Follow log output in real time (like `tail -f`) |

### `medusa-agent config`

Show current agent configuration. Sensitive values (API keys) are masked.

```bash
medusa-agent config
```

### `medusa-agent version`

Show agent version and platform.

```bash
medusa-agent version
```

---

## `medusa` Commands

The `medusa` CLI provides ad-hoc scanning, baselines, and diff for audits and CI/CD.

### Global Options

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

### `medusa scan`

Scan MCP servers for security vulnerabilities.

```bash
medusa scan [OPTIONS]
```

#### Server Discovery

| Option | Description |
|--------|-------------|
| `--http URL` | HTTP/SSE MCP server URL to scan |
| `--stdio CMD` | Stdio MCP server command to scan |
| `--config-file PATH` | Path to MCP client config file |
| `--scan-config PATH` | Path to medusa.yaml scan configuration |
| `--server NAME` | Scan a specific server from config |
| `--no-auto-discover` | Disable automatic server discovery |

#### Output

| Option | Description |
|--------|-------------|
| `-o, --output FORMAT` | Report format: `console`, `json`, `html`, `markdown`, `sarif` |
| `--output-file PATH` | Write report to file |

#### Check Filtering

| Option | Description |
|--------|-------------|
| `--category CATS` | Only run checks in these categories (comma-separated) |
| `--severity SEV` | Minimum severity to include |
| `--checks IDS` | Only run these check IDs (comma-separated) |
| `--exclude-checks IDS` | Skip these check IDs (comma-separated) |

#### Scoring & Compliance

| Option | Description |
|--------|-------------|
| `--fail-on SEV` | Exit code 1 if findings at/above this severity (default: `high`) |
| `--compliance FRAMEWORK` | Evaluate a compliance framework |

#### AI Reasoning

| Option | Description |
|--------|-------------|
| `--reason` | Enable AI reasoning engine |
| `--claude-api-key KEY` | Anthropic API key |
| `--ai-mode MODE` | `byok` (bring-your-own-key) or `proxied` |

#### Legacy Modes

| Option | Description |
|--------|-------------|
| `--static` | Static checks only (default) |
| `--ai` | Legacy AI-only analysis (use `--reason` instead) |
| `--all` | Legacy static + AI combined (use `--reason` instead) |

#### Baseline

| Option | Description |
|--------|-------------|
| `--baseline PATH` | Compare against baseline, show only new findings |
| `--generate-baseline PATH` | Save current findings as a baseline |

#### Other

| Option | Description |
|--------|-------------|
| `--max-concurrency N` | Max parallel server scans (default: 4) |
| `--upload` | Upload results to Medusa dashboard |
| `--api-key KEY` | Medusa API key for upload |

---

### `medusa quickscan`

Run a fast subset of checks for a quick security assessment.

```bash
medusa quickscan [OPTIONS]
```

Accepts the same server discovery and output options as `medusa scan`.

---

### `medusa diff`

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

### `medusa baseline show`

Display contents of a baseline file.

```bash
medusa baseline show BASELINE_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--suppressed-only` | Show only suppressed findings |

---

### `medusa baseline suppress`

Suppress a finding in a baseline by fingerprint.

```bash
medusa baseline suppress BASELINE_FILE FINGERPRINT --reason "text"
```

| Option | Description |
|--------|-------------|
| `--reason TEXT` | Required: reason for suppression |

---

### `medusa baseline unsuppress`

Remove suppression from a finding.

```bash
medusa baseline unsuppress BASELINE_FILE FINGERPRINT
```

---

### `medusa list-checks`

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

### `medusa list-advisories`

List security advisories for scanned servers.

```bash
medusa list-advisories [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--format FMT` | Output format: `table`, `json` |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success / no findings above threshold |
| `1` | Findings at/above `--fail-on` level, or new findings with `--fail-on-new` |
| `2` | Configuration or setup error |
| `3` | No MCP servers found |
