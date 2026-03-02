# CI/CD Integration

Medusa is designed for CI/CD pipelines. It provides exit codes, machine-readable output, baseline comparison, and SARIF integration.

## GitHub Actions

### Basic Security Gate

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  medusa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Medusa
        run: pip install medusa-mcp

      - name: Scan MCP servers
        run: |
          medusa scan \
            -o json \
            --output-file results.json \
            --fail-on high \
            -q
```

### With Baseline (Recommended)

Only fail on **new** findings:

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  medusa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Medusa
        run: pip install medusa-mcp

      - name: Scan with baseline
        run: |
          medusa scan \
            --baseline .medusa-baseline.json \
            -o json \
            --output-file results.json \
            --fail-on high \
            -q

      - name: Upload results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: medusa-results
          path: results.json
```

### With GitHub Code Scanning (SARIF)

```yaml
name: MCP Security Scan
on: [push, pull_request]

permissions:
  security-events: write

jobs:
  medusa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Medusa
        run: pip install medusa-mcp

      - name: Scan MCP servers
        run: |
          medusa scan \
            -o sarif \
            --output-file results.sarif \
            -q || true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### With AI Reasoning

```yaml
      - name: Scan with AI reasoning
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          medusa scan \
            --reason \
            -o json \
            --output-file results.json \
            --fail-on high \
            -q
```

### PR Diff Check

Compare against the base branch's scan:

```yaml
name: Security Diff
on: pull_request

jobs:
  medusa-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Medusa
        run: pip install medusa-mcp

      - name: Run current scan
        run: medusa scan -o json --output-file after.json -q || true

      - name: Checkout base branch scan
        run: |
          git show origin/${{ github.base_ref }}:scan-results.json > before.json 2>/dev/null || echo '{}' > before.json

      - name: Diff scans
        run: medusa diff before.json after.json --fail-on-new
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| `0` | No findings above threshold | Pipeline passes |
| `1` | Findings at/above `--fail-on` level | Pipeline fails |
| `2` | Configuration error | Fix config |
| `3` | No servers found | Check server config |

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Claude API key for `--reason` |
| `MEDUSA_API_KEY` | Dashboard API key for `--upload` |

## Tips

!!! tip "JSON for Piped Output"
    Medusa auto-detects pipes and switches to JSON output. No need for `-o json` when piping: `medusa scan -q | jq .`

!!! tip "Quiet Mode"
    Use `-q` in CI to suppress the banner and progress bar. Only errors are shown.

!!! tip "Baseline in Source Control"
    Commit `.medusa-baseline.json` to your repo. Update it when you address findings or accept risks.
