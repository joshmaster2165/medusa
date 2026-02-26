# Contributing to Medusa

Thank you for your interest in contributing to Medusa. This guide covers the most common contribution: adding a new security check. It also covers code style, testing, and the pull request process.

---

## Adding a New Check

Every check consists of exactly **two files** placed in the appropriate category directory under `src/medusa/checks/<category>/`:

1. **`<check_id>_<short_name>.py`** -- the check implementation
2. **`<check_id>_<short_name>.metadata.yaml`** -- the check metadata

For example, to add a new check `tp006_encoded_payloads` in the `tool_poisoning` category:

```
src/medusa/checks/tool_poisoning/
    tp006_encoded_payloads.py
    tp006_encoded_payloads.metadata.yaml
```

The check is auto-discovered at runtime by `CheckRegistry.discover_checks()`. No registration code or imports are needed.

---

### Step 1: Write the Metadata File

Create `<check_id>_<short_name>.metadata.yaml` with these fields:

```yaml
check_id: tp006
title: Base64-Encoded Payloads in Tool Descriptions
category: tool_poisoning
severity: high
description: >
  One or two sentences describing what the check detects.
risk_explanation: >
  Explain the security risk if this issue is present. What can an
  attacker do? What is the impact?
remediation: >
  Concrete steps the user should take to fix the issue.
references:
  - https://example.com/relevant-resource
  - https://owasp.org/relevant-page
owasp_mcp:
  - "MCP03:2025"
tags:
  - tool_poisoning
  - base64
  - obfuscation
```

#### CheckMetadata Fields

| Field              | Type         | Required | Description |
|--------------------|--------------|----------|-------------|
| `check_id`         | `str`        | Yes      | Unique identifier. Use the category prefix + sequential number (e.g. `tp006`, `auth005`, `iv006`). |
| `title`            | `str`        | Yes      | Human-readable title for the check. |
| `category`         | `str`        | Yes      | Must match the directory name: `tool_poisoning`, `authentication`, `input_validation`, `credential_exposure`, `privilege_scope`, `transport_security`, `integrity`, or `data_protection`. |
| `severity`         | `str`        | Yes      | One of: `critical`, `high`, `medium`, `low`, `informational`. |
| `description`      | `str`        | Yes      | What the check detects (shown in reports and `list-checks`). |
| `risk_explanation`  | `str`        | Yes      | Why this issue is dangerous. |
| `remediation`      | `str`        | Yes      | How to fix the issue. |
| `references`       | `list[str]`  | No       | URLs to relevant specifications, advisories, or blog posts. |
| `owasp_mcp`        | `list[str]`  | No       | OWASP MCP Top 10 requirement IDs this check maps to (e.g. `"MCP03:2025"`). |
| `tags`             | `list[str]`  | No       | Freeform tags for filtering and search. |

---

### Step 2: Write the Check Implementation

Create `<check_id>_<short_name>.py` with a class that inherits from `BaseCheck`:

```python
"""TP-006: Detect base64-encoded payloads in tool descriptions."""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Severity, Status


class EncodedPayloadsCheck(BaseCheck):
    """Check for base64-encoded payloads in tool descriptions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            description = tool.get("description", "")

            # --- Your detection logic here ---
            has_issue = False  # Replace with actual detection
            evidence = ""

            if has_issue:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=f"Tool '{tool_name}' contains encoded payload.",
                        evidence=evidence,
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Emit a PASS finding if all tools were clean
        if not findings and snapshot.tools:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=f"No encoded payloads detected across {len(snapshot.tools)} tool(s).",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
```

#### The BaseCheck Interface

```python
class BaseCheck(ABC):
    @abstractmethod
    def metadata(self) -> CheckMetadata:
        """Return the check's metadata (loaded from the .metadata.yaml sidecar)."""
        ...

    @abstractmethod
    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        """Run the check against a server snapshot. Returns a list of Finding objects."""
        ...
```

Key rules for `execute()`:

- Return an **empty list** if the check is not applicable (e.g. no tools on the server).
- Return **one Finding with `status=Status.PASS`** if the server passed.
- Return **one or more Findings with `status=Status.FAIL`**, one per affected resource (tool, parameter, config entry, etc.).
- **Never** raise exceptions for expected conditions. Return an empty list or a PASS finding instead. Unexpected exceptions are caught by the scan engine and converted to ERROR findings.

---

### ServerSnapshot Fields

The `ServerSnapshot` is the only data your check receives. It is an immutable, frozen dataclass. Checks never get a live connection to the server.

| Field              | Type                  | Description |
|--------------------|-----------------------|-------------|
| `server_name`      | `str`                 | Display name of the MCP server. |
| `transport_type`   | `str`                 | Transport type: `"stdio"`, `"http"`, or `"sse"`. |
| `transport_url`    | `str \| None`         | URL for HTTP/SSE servers. `None` for stdio. |
| `command`          | `str \| None`         | Command used to launch stdio servers. |
| `args`             | `list[str]`           | Arguments passed to the server command. |
| `env`              | `dict[str, str]`      | Environment variables passed to the server process. |
| `tools`            | `list[dict]`          | Tool definitions returned by `tools/list`. Each dict has `name`, `description`, and `inputSchema` keys. |
| `resources`        | `list[dict]`          | Resource definitions returned by `resources/list`. |
| `prompts`          | `list[dict]`          | Prompt definitions returned by `prompts/list`. |
| `capabilities`     | `dict`                | Server capabilities from the `initialize` response. |
| `protocol_version` | `str`                 | MCP protocol version string. |
| `server_info`      | `dict`                | Server metadata from the `initialize` response (name, version). |
| `config_file_path` | `str \| None`         | Path to the config file that defined this server. |
| `config_raw`       | `dict \| None`        | Raw configuration dict for this server entry. |

---

### Step 3: Test Your Check

Create a test file at `tests/unit/test_checks/test_<check_id>.py`:

```python
"""Tests for TP-006: Encoded Payloads."""

import pytest

from medusa.checks.tool_poisoning.tp006_encoded_payloads import EncodedPayloadsCheck
from medusa.core.check import ServerSnapshot
from medusa.core.models import Status


def _make_snapshot(**kwargs) -> ServerSnapshot:
    """Create a minimal ServerSnapshot for testing."""
    defaults = {
        "server_name": "test-server",
        "transport_type": "stdio",
    }
    defaults.update(kwargs)
    return ServerSnapshot(**defaults)


@pytest.fixture
def check() -> EncodedPayloadsCheck:
    return EncodedPayloadsCheck()


class TestEncodedPayloadsCheck:
    async def test_metadata_loads(self, check: EncodedPayloadsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "tp006"
        assert meta.severity.value == "high"

    async def test_pass_when_no_tools(self, check: EncodedPayloadsCheck) -> None:
        snapshot = _make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_pass_when_clean(self, check: EncodedPayloadsCheck) -> None:
        snapshot = _make_snapshot(
            tools=[{"name": "safe_tool", "description": "A normal description."}]
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_fail_when_encoded_payload_detected(self, check: EncodedPayloadsCheck) -> None:
        snapshot = _make_snapshot(
            tools=[
                {
                    "name": "bad_tool",
                    "description": "Normal text aGlkZGVuIGluc3RydWN0aW9ucw== more text",
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)
```

Run the tests:

```bash
# Run all tests
pytest

# Run only your new check's tests
pytest tests/unit/test_checks/test_tp006.py -v

# Run with async support (configured in pyproject.toml)
pytest --asyncio-mode=auto
```

---

## Code Style

This project uses **ruff** for linting/formatting and **mypy** for type checking.

```bash
# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/

# Type check
mypy src/
```

Configuration is in `pyproject.toml`:

- **ruff**: Python 3.12 target, 100-character line length, rules `E`, `F`, `I`, `N`, `W`, `UP`.
- **mypy**: strict mode enabled.

Please ensure `ruff check`, `ruff format --check`, and `mypy` all pass before submitting a PR.

---

## Development Setup

```bash
# Clone the repository
git clone <repo-url>
cd medusa

# Install with dev dependencies (using Poetry)
poetry install

# Or with pip in editable mode
pip install -e ".[dev]"

# Verify everything works
pytest
ruff check src/ tests/
mypy src/
```

---

## Pull Request Process

1. **Create a branch** from `main` with a descriptive name (e.g. `add-check-tp006-encoded-payloads`).
2. **Add your check** (two files: `.py` + `.metadata.yaml`) in the correct category directory.
3. **Add tests** in `tests/unit/test_checks/`.
4. **Run the full suite** and ensure all checks pass:
   ```bash
   pytest
   ruff check src/ tests/
   ruff format --check src/ tests/
   mypy src/
   ```
5. **Update the OWASP mapping** in `src/medusa/compliance/owasp_mcp_top10.yaml` if your check covers a listed requirement.
6. **Open a pull request** with:
   - A clear title (e.g. "Add TP-006: Base64-Encoded Payloads in Tool Descriptions").
   - A description of what the check detects, why it matters, and how you tested it.
   - Link to any relevant specification or advisory.

---

## Check ID Conventions

| Category            | Prefix  | Next available |
|---------------------|---------|----------------|
| Tool Poisoning      | `tp`    | `tp006`        |
| Authentication      | `auth`  | `auth005`      |
| Input Validation    | `iv`    | `iv006`        |
| Credential Exposure | `cred`  | `cred004`      |
| Privilege & Scope   | `priv`  | `priv004`      |
| Transport Security  | `ts`    | `ts001`        |
| Integrity           | `int`   | `int001`       |
| Data Protection     | `dp`    | `dp001`        |

---

## Questions

If you are unsure about anything -- the right category for a check, the appropriate severity, or how to structure detection logic -- open an issue or a draft pull request and ask. We are happy to help.
