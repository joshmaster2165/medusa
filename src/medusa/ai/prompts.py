"""System prompts for AI-powered security analysis."""

from __future__ import annotations

# ── Category-aware prompt template ────────────────────────────────────
# Each AI check fills in {check_list} (the static checks for its
# category) and {category_prefix} (e.g. "tp", "iv") before sending
# to Claude.

CATEGORY_SYSTEM_PROMPT = """\
You are an expert MCP (Model Context Protocol) security auditor. You \
are analyzing an MCP server for security issues in a SPECIFIC category.

IMPORTANT: You MUST evaluate the snapshot against EVERY check listed \
below. Do not skip or skim any checks. For each check, determine \
whether the snapshot shows evidence of that specific issue. You have \
access to the same check definitions that a static scanner uses, but \
you should apply SEMANTIC UNDERSTANDING — catch issues that pattern \
matching cannot.

{check_list}

INSTRUCTIONS:
1. Systematically evaluate the snapshot against EACH check above
2. For each issue found, use the check_id of the matching static \
check (e.g. tp001, iv003)
3. If you find an issue that doesn't match any specific check but is \
clearly in this category, use check_id "{category_prefix}0ai"
4. Prefix your title with "[AI] "
5. Provide concrete evidence from the snapshot data
6. Only report findings with clear supporting evidence
7. Do NOT flag theoretical risks without evidence in the provided data
8. Severity must match the ACTUAL impact, not just the category

Return ONLY a JSON object:
{{
  "checks_evaluated": ["xx001", "xx002", "...every check_id you analyzed"],
  "findings": [
    {{
      "check_id": "xx001",
      "resource_type": "tool | resource | prompt | server",
      "resource_name": "name",
      "severity": "critical | high | medium | low",
      "title": "[AI] Brief title",
      "status_extended": "Detailed explanation",
      "evidence": "Specific text or pattern from the snapshot",
      "remediation": "Actionable fix",
      "owasp_mcp": ["MCP01:2025"]
    }}
  ]
}}

If no issues found, return: {{"checks_evaluated": [...], "findings": []}}

OWASP MCP codes: MCP01 (Prompt Injection), MCP02 (Tool Misuse), \
MCP03 (Tool Poisoning), MCP04 (Privilege Escalation), MCP05 (Data \
Exfiltration), MCP06 (Indirect Prompt Injection), MCP07 (Unauthorized \
Access), MCP08 (Config Exposure), MCP09 (Logging Gaps), MCP10 (Supply \
Chain)
"""

# Keep the old constant as an alias for backwards compatibility
COMPREHENSIVE_SYSTEM_PROMPT = CATEGORY_SYSTEM_PROMPT


def build_analysis_payload(
    server_name: str,
    transport_type: str,
    tools: list[dict],
    resources: list[dict],
    prompts: list[dict],
    capabilities: dict,
    config_raw: dict | None,
) -> str:
    """Build the user-content payload from a server snapshot."""
    import json

    sections: list[str] = []

    sections.append(f"SERVER: {server_name}")
    sections.append(f"TRANSPORT: {transport_type}")

    if tools:
        sections.append(f"\nTOOLS ({len(tools)}):")
        sections.append(json.dumps(tools, indent=2, default=str))

    if resources:
        sections.append(f"\nRESOURCES ({len(resources)}):")
        sections.append(json.dumps(resources, indent=2, default=str))

    if prompts:
        sections.append(f"\nPROMPTS ({len(prompts)}):")
        sections.append(json.dumps(prompts, indent=2, default=str))

    if capabilities:
        sections.append("\nCAPABILITIES:")
        sections.append(json.dumps(capabilities, indent=2, default=str))

    if config_raw:
        # Redact potential secrets before sending to AI
        safe_config = _redact_secrets(config_raw)
        sections.append("\nCONFIGURATION:")
        sections.append(json.dumps(safe_config, indent=2, default=str))

    return "\n".join(sections)


def _redact_secrets(config: dict) -> dict:
    """Shallow redaction of values that look like secrets."""
    secret_keys = {
        "api_key",
        "apikey",
        "secret",
        "password",
        "token",
        "authorization",
    }
    redacted: dict = {}
    for key, value in config.items():
        if isinstance(value, dict):
            redacted[key] = _redact_secrets(value)
        elif isinstance(value, str) and key.lower() in secret_keys:
            redacted[key] = "***REDACTED***"
        else:
            redacted[key] = value
    return redacted
