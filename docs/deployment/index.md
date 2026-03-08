# Deployment Overview

Medusa deploys as a lightweight agent daemon on each endpoint. The agent
auto-discovers MCP client configurations, inserts gateway proxies, enforces
security policies, and uploads telemetry to the Medusa dashboard.

---

## Platform Support

| Platform   | Service Mechanism | Architecture | Minimum Version       |
| ---------- | ----------------- | ------------ | --------------------- |
| **macOS**  | launchd           | ARM64, x86   | macOS 13 (Ventura)+   |
| **Windows**| Windows Service   | x86_64       | Windows 10+           |
| **Linux**  | systemd           | x86_64, ARM64| Ubuntu 22+, Debian 12+, RHEL 9+ |

**Requirements (all platforms):**

- Python 3.12+
- pip (or pipx)
- Network access to `*.supabase.co` for dashboard sync

---

## Supported MCP Clients

The agent auto-discovers and proxies these MCP clients:

| Client          | macOS | Windows | Linux |
| --------------- | ----- | ------- | ----- |
| Claude Desktop  | Yes   | Yes     | Yes   |
| Cursor          | Yes   | Yes     | Yes   |
| Windsurf        | Yes   | Yes     | Yes   |
| VS Code         | Yes   | Yes     | Yes   |
| Claude Code     | Yes   | Yes     | Yes   |
| Gemini CLI      | Yes   | Yes     | Yes   |
| Zed             | Yes   | Yes     | Yes   |
| Cline           | Yes   | Yes     | Yes   |
| Roo Code        | Yes   | Yes     | Yes   |
| Continue.dev    | Yes   | Yes     | Yes   |
| Amazon Q        | Yes   | Yes     | Yes   |
| GitHub Copilot  | Yes   | Yes     | Yes   |

!!! note
    Only **stdio** servers (entries with a `command` field) are proxied.
    HTTP/SSE servers are left unchanged.

---

## How the Gateway Works

When the agent installs, it rewrites each MCP client's config so that every
stdio server is launched through the Medusa gateway proxy:

**Before:**
```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-everything"]
}
```

**After:**
```json
{
  "command": "medusa-agent",
  "args": [
    "gateway-proxy", "--",
    "npx", "-y", "@modelcontextprotocol/server-everything"
  ]
}
```

The proxy intercepts every JSON-RPC message, evaluates it against the active
policy, and either allows, blocks, or coaches. All events are logged locally
and uploaded to the dashboard.

---

## Deployment Guides

Choose your platform:

- **[Windows -- Manual Deployment](windows/manual-deployment.md)**
- **[Windows -- Enterprise Deployment (Intune / GPO)](windows/enterprise-deployment.md)**
- **[Windows -- Confirming Deployment](windows/confirming-deployment.md)**
- **[macOS -- Manual Deployment](macos/manual-deployment.md)**
- **[macOS -- Enterprise Deployment (Kandji / Jamf)](macos/enterprise-deployment.md)**
- **[macOS -- Confirming Deployment](macos/confirming-deployment.md)**
- **[Linux -- Manual Deployment](linux/manual-deployment.md)**
- **[Linux -- Confirming Deployment](linux/confirming-deployment.md)**
