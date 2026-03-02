# Baselines & Diff

Medusa's baseline and diff system lets you track finding changes over time, suppress accepted risks, and focus CI/CD alerts on **new** issues only.

## Baselines

A baseline is a snapshot of findings from a scan. Subsequent scans can compare against it to show only new findings.

### Generate a Baseline

```bash
medusa scan --generate-baseline .medusa-baseline.json
```

This creates a `.medusa-baseline.json` file containing fingerprints of all FAIL findings:

```json
{
  "version": 1,
  "created_at": "2026-03-02T14:30:00+00:00",
  "medusa_version": "0.1.0",
  "scan_id": "abc123",
  "entries": [
    {
      "fingerprint": "a1b2c3d4e5f67890",
      "check_id": "tp002",
      "server_name": "my-server",
      "resource_name": "execute_command",
      "severity": "high",
      "check_title": "Tool description contains hidden instructions",
      "suppressed": false,
      "suppression_reason": null
    }
  ]
}
```

### Scan Against a Baseline

```bash
medusa scan --baseline .medusa-baseline.json
```

Output only shows **new** findings not in the baseline. The console displays:

```
  ▸ Baseline: 2 new, 5 baselined, 1 resolved
```

### Fingerprinting

Each finding is fingerprinted by:

- `check_id` — which check found it
- `server_name` — which server it's on
- `resource_type` — tool/resource/prompt/server
- `resource_name` — the specific resource
- `severity` — the severity level

This means the same finding always gets the same fingerprint, even if the status text changes between scans.

## Suppression

Mark known/accepted findings as suppressed so they don't appear in reports:

### Suppress a Finding

```bash
medusa baseline suppress .medusa-baseline.json a1b2c3d4e5f67890 \
  --reason "Accepted risk per JIRA-1234"
```

### Unsuppress a Finding

```bash
medusa baseline unsuppress .medusa-baseline.json a1b2c3d4e5f67890
```

### View Baseline

```bash
# Show all entries
medusa baseline show .medusa-baseline.json

# Show only suppressed entries
medusa baseline show .medusa-baseline.json --suppressed-only
```

## Diff

Compare two JSON scan results to see what changed:

```bash
medusa diff before.json after.json
```

### Output

The diff shows:

- **New findings** — issues introduced since the last scan
- **Resolved findings** — issues that are no longer present
- **Score changes** — per-server and aggregate score deltas

```
┌─ Scan Diff ──────────────────────────────────────────┐
│ Score: 8.0/10 (B) → 6.5/10 (C)  [-1.5]             │
│                                                       │
│ 3 new findings  |  1 resolved  |  0 severity changes │
└───────────────────────────────────────────────────────┘
```

### JSON Output

```bash
medusa diff before.json after.json -o json --output-file changes.json
```

### CI/CD: Fail on New Findings

```bash
medusa diff before.json after.json --fail-on-new
```

Exit code 1 if any new findings are detected — perfect for pull request checks.

## CI/CD Workflow

### Recommended Pattern

```yaml
# .github/workflows/security.yml
jobs:
  medusa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Medusa
        run: pip install medusa-mcp

      - name: Run security scan
        run: |
          medusa scan \
            --baseline .medusa-baseline.json \
            -o json \
            --output-file scan-results.json \
            --fail-on high

      - name: Check for new findings
        if: always()
        run: |
          medusa diff .medusa-baseline.json scan-results.json --fail-on-new
```

### Updating the Baseline

When you've addressed findings or accepted risks, regenerate the baseline:

```bash
medusa scan --generate-baseline .medusa-baseline.json
git add .medusa-baseline.json
git commit -m "Update security baseline"
```

!!! tip "Commit Your Baseline"
    Check `.medusa-baseline.json` into source control so your team shares the same baseline.
