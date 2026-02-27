# Medusa

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Checks: 435](https://img.shields.io/badge/checks-435-brightgreen.svg)](#check-categories)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP-MCP%20Top%2010-orange.svg)](#owasp-mcp-top-10-compliance)

**Security scanner for MCP servers**

Medusa is an open-source CLI tool that connects to [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers, runs **435 security checks** across **24 categories**, scores findings on a 0--10 scale, and generates reports and dashboards. It auto-discovers servers from Claude Desktop, Cursor, Windsurf, and custom config files so you can audit your MCP setup with a single command.

---

## Features

- **Auto-discovery** -- finds MCP servers from Claude Desktop, Cursor, Windsurf, and custom config files without manual configuration.
- **435 built-in checks** across 24 categories including tool poisoning, authentication, input validation, credential exposure, privilege/scope, transport security, data protection, integrity, session management, error handling, rate limiting, SSRF/network, agentic behavior, sampling security, context security, resource security, multi-tenant isolation, secrets management, server hardening, governance, audit logging, supply chain, and server identity.
- **Severity scoring** -- each server receives a 0--10 numeric score and an A--F letter grade.
- **Multiple output formats** -- JSON (machine-readable), HTML (interactive dashboard), and Markdown.
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

---

## Check Categories

Medusa ships with **435 checks** across **24 categories**:

| Category               | Prefix     | Checks | Description                                                                 |
|------------------------|------------|--------|-----------------------------------------------------------------------------|
| Tool Poisoning         | `tp0xx`    | 15     | Hidden instructions, prompt injection, tool shadowing, rug pull detection, cross-server collisions |
| Authentication         | `auth0xx`  | 30     | Missing auth, weak OAuth, token storage, JWT issues, CSRF, MFA, credential rotation |
| Input Validation       | `iv0xx`    | 30     | Command injection, path traversal, SQL injection, schema validation, deserialization |
| Credential Exposure    | `cred0xx`  | 10     | Secrets in config, env var leakage, secrets in definitions, hardcoded tokens |
| Privilege & Scope      | `priv0xx`  | 15     | Filesystem access, network access, shell execution, privilege escalation |
| Transport Security     | `ts0xx`    | 20     | Unencrypted transport, TLS validation, certificate issues, CORS, WebSocket security |
| Data Protection        | `dp0xx`    | 29     | PII exposure, data leakage, encryption, consent, COPPA, health/financial data |
| Integrity              | `intg0xx`  | 17     | Version pinning, lockfiles, SBOM, dependency confusion, typosquatting |
| Session Management     | `sess0xx`  | 20     | Session fixation, timeout, hijacking, cookie security, WebSocket sessions |
| Error Handling         | `err0xx`   | 15     | Stack traces, error codes, injection, graceful degradation, log injection |
| Rate Limiting          | `rl0xx`    | 15     | Missing rate limits, DDoS protection, burst control, cost-based limiting |
| SSRF & Network         | `ssrf0xx`  | 15     | Private IP access, cloud metadata, DNS rebinding, egress control |
| Agentic Behavior       | `agent0xx` | 20     | Unauthorized tool chaining, goal drift, memory poisoning, self-modification |
| Sampling Security      | `samp0xx`  | 15     | Sampling abuse, model manipulation, prompt leakage, budget exhaustion |
| Context Security       | `ctx0xx`   | 10     | Context overflow, token exhaustion, role confusion, multi-turn manipulation |
| Resource Security      | `res0xx`   | 20     | URI injection, unauthorized access, SSRF via resources, dependency chains |
| Multi-Tenant           | `mt0xx`    | 10     | Tenant isolation, cross-tenant access, data leakage, impersonation |
| Secrets Management     | `sm0xx`    | 10     | Plaintext secrets, rotation, vault integration, encryption at rest |
| Server Hardening       | `sh0xx`    | 15     | Default configs, unnecessary features, security headers, directory listing |
| Governance             | `gov0xx`   | 20     | Security policies, access review, vulnerability management, compliance |
| Audit Logging          | `audit0xx` | 10     | Missing logging, audit trails, log integrity, rotation, forensic capability |
| Supply Chain           | `sc0xx`    | 8      | Untrusted sources, abandoned deps, install scripts, native binaries |
| Server Identity        | `shadow0xx`| 7      | Duplicate names, missing metadata, suspicious origins, version spoofing |
| Prompt Security        | `pi0xx`    | 39     | Prompt injection patterns, encoding attacks, multi-language injection |

Run `medusa list-checks` to see the full table with OWASP MCP mappings.

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
