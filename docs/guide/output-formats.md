# Output Formats

Medusa supports 5 output formats for different use cases.

## Console (Default)

Rich terminal output with color-coded findings, severity badges, and scoring.

```bash
medusa scan
```

**Features:**

- Grade circle (A-F)
- Severity summary bar
- Per-server score breakdown
- Failed findings table with expandable details
- AI reasoning section (when `--reason` is used)
- Compliance section (when `--compliance` is used)

!!! info "Pipe Detection"
    When stdout is piped, Medusa automatically switches to JSON output.

## JSON

Machine-readable output using Pydantic serialization.

```bash
medusa scan -o json --output-file results.json
```

The JSON contains the complete `ScanResult` model:

```json
{
  "scan_id": "abc123",
  "timestamp": "2026-03-02T14:30:00+00:00",
  "medusa_version": "0.1.0",
  "scan_duration_seconds": 12.5,
  "servers_scanned": 2,
  "total_findings": 15,
  "findings": [...],
  "server_scores": [...],
  "aggregate_score": 7.5,
  "aggregate_grade": "B",
  "compliance_results": {...},
  "reasoning_results": {...}
}
```

## HTML Dashboard

Self-contained interactive HTML report — no external dependencies.

```bash
medusa scan -o html --output-file report.html
```

**Features:**

- Dark-themed professional design
- Grade visualization
- Severity filter buttons
- Server score grid
- Expandable findings with details
- Compliance results table
- Fully self-contained (embedded CSS + JS)

## Markdown

GitHub-friendly markdown report.

```bash
medusa scan -o markdown --output-file report.md
```

**Sections:**

- Summary header with grade, score, date
- Severity summary table
- Server scores table
- Findings grouped by severity
- Compliance requirements table

## SARIF

[Static Analysis Results Interchange Format](https://sarifweb.azurewebsites.net/) for CI/CD integration.

```bash
medusa scan -o sarif --output-file results.sarif
```

**Compatible with:**

- GitHub Code Scanning
- Azure DevOps
- VS Code SARIF Viewer extension
- Any SARIF 2.1.0 compliant tool

**GitHub Code Scanning integration:**

```yaml
# .github/workflows/medusa.yml
- name: Run Medusa scan
  run: medusa scan -o sarif --output-file results.sarif -q

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Multiple Formats

To generate multiple formats in one scan, run the scan once with JSON output, then use the JSON file as input for other tools:

```bash
# Generate JSON result
medusa scan -o json --output-file results.json

# Use jq to extract findings
jq '.findings[] | select(.status == "fail")' results.json
```

Or run multiple scans (they're fast):

```bash
medusa scan -o html --output-file report.html
medusa scan -o sarif --output-file results.sarif
```
