<p align="center">
  <img src="docs/logo.svg" alt="Medusa Logo" width="300">
</p>
<p align="center">
  <strong>Security scanner for MCP servers</strong>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python 3.12+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-green.svg" alt="License: Apache 2.0"></a>
  <a href="#check-categories"><img src="https://img.shields.io/badge/checks-559-brightgreen.svg" alt="Checks: 559"></a>
  <a href="#check-categories"><img src="https://img.shields.io/badge/categories-26-brightgreen.svg" alt="Categories: 26"></a>
  <a href="#owasp-mcp-top-10-compliance"><img src="https://img.shields.io/badge/OWASP-MCP%20Top%2010-orange.svg" alt="OWASP MCP Top 10"></a>
</p>

<p align="center">
  Medusa is an open-source CLI tool that connects to <a href="https://modelcontextprotocol.io">Model Context Protocol (MCP)</a> servers, runs <strong>559 security checks</strong> across <strong>26 categories</strong>, scores findings on a 0–10 scale, and generates reports and dashboards. An optional <strong>AI reasoning engine</strong> validates findings, detects attack chains, and discovers gaps. It auto-discovers servers from Claude Desktop, Cursor, Windsurf, and custom config files so you can audit your MCP setup with a single command.
</p>

---

## Features

- **Auto-discovery** -- finds MCP servers from Claude Desktop, Cursor, Windsurf, and custom config files without manual configuration.
- **559 built-in checks** across 26 categories including tool poisoning (56 TTP-based checks), input validation, credential exposure, authentication, data protection, agentic behavior, resource security, privilege/scope, prompt security, governance, integrity, transport security, session management, SSRF/network, secrets management, server hardening, rate limiting, error handling, sampling security, supply chain, context security, multi-tenant isolation, audit logging, server identity, and toxic flows.
- **AI reasoning layer** -- run static checks first, then send findings to Claude for validation, false-positive detection, attack chain correlation, gap discovery, and prioritized remediation (`--reason`).
- **Severity scoring** -- each server receives a 0--10 numeric score and an A--F letter grade.
- **Multiple output formats** -- Console (Rich tables), JSON (machine-readable), HTML (interactive dashboard), Markdown, and SARIF.
- **CI/CD integration** -- `--fail-on` flag returns a non-zero exit code when findings meet or exceed a severity threshold.
- **OWASP MCP Top 10 compliance** -- map findings to the OWASP MCP Top 10 2025 framework.
- **Extensible** -- add custom checks by dropping a `.py` + `.metadata.yaml` pair into the checks directory.
- **Safe by design** -- checks operate on an immutable `ServerSnapshot`; they never invoke tools or modify server state.

---

## Prerequisites

- **Python 3.12+**

## Quick Start

```bash
pip install medusa-mcp
medusa scan
```

Medusa auto-discovers your locally configured MCP servers, runs all checks, and prints a JSON report with scores to stdout.

### Development Install

```bash
git clone https://github.com/joshmaster2165/medusa.git
cd medusa
poetry install
poetry run medusa scan
```

---

## Usage

### Auto-discover and scan all configured servers

```bash
medusa scan
```

### Scan a specific HTTP server

```bash
medusa scan --http https://mcp.example.com
```

### Static scan + AI reasoning (recommended AI mode)

```bash
medusa scan --reason --claude-api-key sk-ant-...
```

### Generate an HTML dashboard

```bash
medusa scan -o html --output-file report.html
```

### CI/CD -- fail the build on high-severity findings

```bash
medusa scan -o json --fail-on high
```

### List all available checks

```bash
medusa list-checks
```

### Scan with OWASP MCP Top 10 compliance evaluation

```bash
medusa scan --compliance owasp_mcp_top10
```

### Filter checks by category or severity

```bash
medusa scan --category tool_poisoning,authentication
medusa scan --severity critical
```

### Exclude specific checks

```bash
medusa scan --exclude-checks tp005,iv005
```

### Scan modes

| Flag | Behavior |
|------|----------|
| *(default)* | Static checks only (559 checks, fast, free) |
| `--reason` | Static + AI reasoning engine (recommended) |
| `--deep` | Alias for `--reason` |

The `--reason` flag runs all 559 static checks first, then sends the findings and server snapshot to Claude as a reasoning engine. The AI validates findings, identifies false positives, discovers attack chains across categories, finds gaps the static checks missed, and produces an executive summary with prioritized remediation.

---

## Check Categories

Medusa ships with **559 checks** across **26 categories**:

| Category               | Prefix      | Checks | Description                                                                 |
|------------------------|-------------|--------|-----------------------------------------------------------------------------|
| Tool Poisoning         | `tp0xx`     | 56     | Hidden instructions, prompt injection, tool shadowing, rug pull detection, ANSI escape injection, jailbreak patterns, system impersonation, name confusion attacks, TTP-based behavioral analysis |
| Input Validation       | `iv0xx`     | 47     | Command injection, path traversal, SQL/NoSQL injection, LDAP, SSRF, XXE, SSTI, header injection, regex DoS, schema validation, shell metachar defaults |
| Data Protection        | `dp0xx`     | 34     | PII exposure, data leakage, encryption, consent, exfiltration channels, full filesystem control, data retention |
| Authentication         | `auth0xx`   | 30     | Missing auth, weak OAuth, token storage, JWT issues, CSRF, MFA, credential rotation, insecure transport credentials |
| Agentic Behavior       | `agent0xx`  | 27     | Unauthorized tool chaining, goal drift, memory poisoning, destructive tool confirmation, delegation depth limits, self-modification |
| Credential Exposure    | `cred0xx`   | 25     | Secrets in config, env var leakage, credential harvesting tools, sensitive file references, API key patterns, cloud credentials |
| Resource Security      | `res0xx`    | 25     | URI injection, unauthorized access, SSRF via resources, dependency chains, template injection |
| Privilege & Scope      | `priv0xx`   | 26     | Filesystem access, network access, unconstrained shell execution, admin tools without auth, privilege escalation |
| Governance             | `gov0xx`    | 22     | Security policies, access review, vulnerability management, compliance, data classification |
| Integrity              | `intg0xx`   | 20     | Version pinning, lockfiles, SBOM, dependency confusion, typosquatting, reproducible builds |
| Prompt Security        | `pmt0xx`    | 20     | Prompt injection patterns, encoding attacks, multi-language injection, delimiter abuse |
| Session Management     | `sess0xx`   | 20     | Session fixation, timeout, hijacking, cookie security, WebSocket sessions |
| SSRF & Network         | `ssrf0xx`   | 22     | Private IP access, cloud metadata, DNS rebinding, egress control, dangerous URI schemes, internal service discovery |
| Secrets Management     | `sm0xx`     | 20     | Plaintext secrets, rotation, vault integration, encryption at rest, key derivation |
| Transport Security     | `ts0xx`     | 19     | Unencrypted transport, TLS validation, certificate issues, CORS, WebSocket security |
| Server Hardening       | `hard0xx`   | 18     | Default configs, unnecessary features, security headers, directory listing, debug endpoints |
| Error Handling         | `err0xx`    | 15     | Stack traces, error codes, injection, graceful degradation, log injection |
| Rate Limiting          | `dos0xx`    | 15     | Missing rate limits, DDoS protection, burst control, cost-based limiting |
| Sampling Security      | `samp0xx`   | 15     | Sampling abuse, model manipulation, prompt leakage, budget exhaustion |
| Context Security       | `ctx0xx`    | 13     | Context overflow, token exhaustion, prompt argument injection, context shadowing, persistent state injection |
| Supply Chain           | `sc0xx`     | 13     | Untrusted sources, abandoned deps, install scripts, native binaries, lockfile poisoning |
| Multi-Tenant           | `mt0xx`     | 10     | Tenant isolation, cross-tenant access, data leakage, impersonation |
| Audit Logging          | `audit0xx`  | 10     | Missing logging, audit trails, log integrity, rotation, forensic capability |
| Toxic Flows            | `toxic0xx`  | 10     | Dangerous data flow patterns, cross-tool contamination |
| Server Identity        | `shadow0xx` | 7      | Duplicate names, missing metadata, suspicious origins, version spoofing |

Run `medusa list-checks` to see the full table with OWASP MCP mappings.

---

## AI Reasoning Layer

The `--reason` flag enables a two-phase architecture: **static checks first, AI reasoning second**.

```
Phase 1: Static Scan (fast, free, deterministic)
  ServerSnapshot -> 559 static checks -> list[Finding]

Phase 2: AI Reasoning Engine (1-2 API calls per server)
  (snapshot + findings) -> Claude -> ReasoningResult
    A. Validate: confidence score per finding (0.0-1.0)
    B. Filter: false positive identification with reasoning
    C. Correlate: attack chain detection across findings
    D. Discover: gap findings static checks missed
    E. Prioritize: executive summary + remediation order
```

The reasoning layer receives the compact static results instead of re-analyzing raw data, making it ~90% cheaper than legacy `--ai` mode (1-2 API calls vs 24). The AI sees all findings at once, enabling cross-category correlation that isolated checks cannot detect.

```bash
# Run static + AI reasoning
medusa scan --reason --claude-api-key sk-ant-...

# Or set the key via environment variable
export ANTHROPIC_API_KEY=sk-ant-...
medusa scan --reason
```

The enhanced report includes:
- **Confidence annotations** on each finding (confirmed / likely / uncertain / likely false positive)
- **Attack chains** linking related findings into exploitation narratives
- **False positive identification** with specific reason codes
- **Gap discoveries** for issues the static checks missed
- **Executive summary** with top remediation priorities

---

## Scoring

Each server receives a **numeric score from 0.0 to 10.0** and a **letter grade**:

| Score Range | Grade |
|-------------|-------|
| 9.0 -- 10.0 | A     |
| 7.0 -- 8.9  | B     |
| 5.0 -- 6.9  | C     |
| 3.0 -- 4.9  | D     |
| 0.0 -- 2.9  | F     |

The score is calculated by deducting weighted penalties for each failed check:

| Severity      | Weight |
|---------------|--------|
| Critical      | 10.0   |
| High          | 7.0    |
| Medium        | 4.0    |
| Low           | 1.5    |
| Informational | 0.0    |

A server with no failures scores 10.0 (grade A). The aggregate score across multiple servers is a weighted average based on the number of checks run per server.

### Severity Caps

To ensure critical findings are properly reflected in the score, Medusa applies severity-based caps that prevent a server from receiving a high grade when serious vulnerabilities exist:

| Condition | Maximum Score | Effect |
|-----------|---------------|--------|
| 1 CRITICAL finding | 6.9 | Cannot exceed grade C |
| Each additional CRITICAL | −0.3 | Progressive cap reduction |
| 5+ HIGH findings | 7.9 | Cannot exceed grade B |
| Each additional HIGH beyond 5 | −0.05 | Gradual cap reduction |

For example, a server with 7 critical findings has a cap of `6.9 - (6 × 0.3) = 5.1` (Grade C), regardless of how many checks pass. This ensures that the presence of critical vulnerabilities is always visible in the score, even when the vast majority of checks pass.

---

## OWASP MCP Top 10 Compliance

Medusa maps every check to the [OWASP MCP Top 10 2025](https://owasp.org/www-project-mcp-top-10/) framework. Run a compliance evaluation with:

```bash
medusa scan --compliance owasp_mcp_top10
```

The report will include a per-requirement pass/fail status with full coverage across all 10 items:

- MCP01: Token Mismanagement & Secret Exposure
- MCP02: Excessive Permission Scope
- MCP03: Tool Poisoning
- MCP04: Software Supply Chain Attacks
- MCP05: Command Injection
- MCP06: Prompt Injection / Intent Flow Subversion
- MCP07: Insufficient Authentication & Authorization
- MCP08: Lack of Audit and Telemetry
- MCP09: Shadow MCP Servers
- MCP10: Context Injection & Over-Sharing

---

## Configuration

Create a `medusa.yaml` file in your project root to customize scan behaviour:

```yaml
version: "1"

discovery:
  auto_discover: true
  config_files:
    - ~/.config/claude/claude_desktop_config.json
  servers:
    - name: my-api-server
      transport: http
      url: https://mcp.internal.example.com
      headers:
        Authorization: "Bearer ${MCP_TOKEN}"
    - name: local-tools
      transport: stdio
      command: npx
      args: ["-y", "@my-org/mcp-tools"]
      env:
        API_KEY: "${API_KEY}"

checks:
  exclude:
    - tp005
    - iv005
  categories: []
  min_severity: low

scoring:
  fail_threshold: high
  max_findings: 0

output:
  formats:
    - json
  directory: ./medusa-reports
  include_evidence: true
  include_passing: false

compliance:
  frameworks:
    - owasp_mcp_top10

connection:
  timeout: 30
  retries: 2
  parallel: 4
```

Medusa searches for configuration in this order: `medusa.yaml`, `medusa.yml`, `.medusa.yaml`. Use `--scan-config` to specify an explicit path.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on adding new checks, running the test suite, and submitting pull requests.

---

## Issues

Found a bug or have a feature request? [Open an issue](https://github.com/joshmaster2165/medusa/issues).

## License

Apache 2.0. See [LICENSE](LICENSE) for details.
