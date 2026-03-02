# Configuration

Medusa supports two configuration layers:

1. **Scan config** (`medusa.yaml`) — controls what to scan and how
2. **User config** (`~/.medusa/config.yaml`) — stores API keys and preferences

## Scan Configuration

Create a `medusa.yaml` in your project root:

```yaml
version: "1"

discovery:
  auto_discover: true
  servers:
    - name: my-server
      transport: http
      url: http://localhost:3000/mcp
    - name: local-tools
      transport: stdio
      command: npx
      args: ["my-mcp-tools"]
      env:
        NODE_ENV: production

checks:
  exclude:
    - ai001  # Skip specific checks
  categories:
    - tool_poisoning
    - credential_exposure
  min_severity: low

scoring:
  fail_threshold: high

output:
  formats: [json, html]
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

### Config Search Paths

Medusa searches for config files in this order:

1. `--scan-config path/to/config.yaml` (explicit)
2. `./medusa.yaml`
3. `./medusa.yml`
4. `./.medusa.yaml`

### Environment Variables

Use `${ENV_VAR}` syntax for secrets:

```yaml
discovery:
  servers:
    - name: production
      transport: http
      url: ${MCP_SERVER_URL}
      headers:
        Authorization: "Bearer ${MCP_AUTH_TOKEN}"
```

## User Configuration

Run the setup wizard:

```bash
medusa configure
```

Or set values directly:

```bash
medusa configure --api-key sk_medusa_abc123
medusa configure --claude-api-key sk-ant-... --ai-mode byok
```

Settings are stored in `~/.medusa/config.yaml`:

```yaml
api_key: sk_medusa_abc123
dashboard_url: https://app.medusa.security/api/v1/reports
claude_api_key: sk-ant-...
claude_model: claude-sonnet-4-20250514
ai_mode: byok
```

### View Current Settings

```bash
medusa settings
```

API keys are masked in the output for security.

## Configuration Reference

| Section | Key | Type | Default | Description |
|---------|-----|------|---------|-------------|
| `discovery` | `auto_discover` | bool | `true` | Auto-discover from known configs |
| `discovery` | `config_files` | list[str] | `[]` | Additional config files to scan |
| `discovery` | `servers` | list | `[]` | Explicit server definitions |
| `checks` | `include` | list[str] | `[]` | Only run these check IDs |
| `checks` | `exclude` | list[str] | `[]` | Skip these check IDs |
| `checks` | `categories` | list[str] | `[]` | Only run these categories |
| `checks` | `min_severity` | str | `"low"` | Minimum severity to include |
| `scoring` | `fail_threshold` | str | `"high"` | Exit code 1 if findings at this level |
| `output` | `formats` | list[str] | `["json"]` | Output formats |
| `output` | `directory` | str | `"./medusa-reports"` | Report output directory |
| `compliance` | `frameworks` | list[str] | `[]` | Compliance frameworks to evaluate |
| `connection` | `timeout` | int | `30` | Connection timeout in seconds |
| `connection` | `retries` | int | `2` | Connection retry attempts |
| `connection` | `parallel` | int | `4` | Max parallel server scans |
