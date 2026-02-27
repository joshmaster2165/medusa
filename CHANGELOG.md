# Changelog

All notable changes to Medusa will be documented in this file.

## [0.1.0] - 2025-02-27

### Added

- **435 security checks** across **24 categories** covering tool poisoning, authentication, input validation, credential exposure, privilege escalation, transport security, data protection, integrity, session management, error handling, rate limiting, SSRF, agentic behavior, sampling security, context security, resource security, multi-tenant isolation, secrets management, server hardening, governance, audit logging, supply chain, server identity, and prompt security.
- **Auto-discovery** of MCP servers from Claude Desktop, Cursor, and Windsurf configuration files.
- **Scoring engine** with 0-10 numeric scores and A-F letter grades per server.
- **4 output formats**: JSON, HTML (interactive dashboard), Markdown, and SARIF (for CI/CD integration).
- **OWASP MCP Top 10 2025** compliance evaluation framework.
- **Parallel scanning** with configurable concurrency and progress bar.
- **Configuration file** support (`medusa.yaml`) with environment variable expansion.
- **CLI** with `medusa scan` and `medusa list-checks` commands, severity filtering, check exclusion, and `--fail-on` threshold for CI/CD pipelines.
