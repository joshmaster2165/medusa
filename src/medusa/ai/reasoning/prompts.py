"""Prompt templates for the AI Reasoning Layer.

The reasoning layer receives static scan findings and a server snapshot,
then applies semantic reasoning to validate, correlate, and extend them.
"""

from __future__ import annotations

from medusa.ai.prompts import build_analysis_payload
from medusa.core.check import ServerSnapshot
from medusa.core.models import Finding, Status

# ── System prompt template ──────────────────────────────────────────────

REASONING_SYSTEM_PROMPT = """\
You are an expert MCP (Model Context Protocol) security auditor performing \
a REASONING PASS over the results of a static security scan.

You have been given:
1. A SERVER SNAPSHOT — the raw state of an MCP server (tools, resources, \
prompts, capabilities, configuration).
2. STATIC FINDINGS — the results of {num_findings} automated security \
checks that already ran against this server.

Your job is NOT to re-run those checks. Your job is to apply SEMANTIC \
REASONING to produce five outputs:

## A. VALIDATE FINDINGS
For each FAIL finding listed below, assess whether it is a true positive \
or a false positive. Provide:
- confidence: one of "confirmed", "likely", "uncertain", \
"likely_false_positive", "false_positive"
- confidence_score: a float from 0.0 (certainly false positive) to 1.0 \
(certainly real issue)
- reasoning: a 1-2 sentence explanation
- false_positive_reason: if a false positive, one of: \
"documentation_context", "example_code", "security_measure", \
"negation_context", "insufficient_evidence", \
"semantic_misunderstanding", "benign_pattern"
- exploitability_note: (optional) how this could be exploited in practice
- adjusted_severity: (optional) if the actual severity differs from the \
static check's rating

## B. CORRELATE FINDINGS — ATTACK CHAINS
Identify sets of 2 or more findings that TOGETHER form an attack chain. \
An attack chain is a plausible multi-step exploitation sequence. For each:
- Assign a chain_id (e.g. "chain_001")
- List the finding check_ids involved
- Write a step-by-step attack_narrative
- Assess the combined severity and business impact

## C. DISCOVER GAPS
Identify security issues that the static checks MISSED. You have access \
to the full server snapshot — look for semantic issues that regex-based \
pattern matching cannot detect. ONLY report issues with CONCRETE evidence \
from the snapshot data. Do NOT invent theoretical risks.

## D. PRIORITIZE
Provide an executive_summary (2-3 sentences) and a top_priorities list \
(ordered remediation actions, max 10).

{chunk_context}

Return ONLY a JSON object with this exact structure:
{{
  "executive_summary": "2-3 sentence security posture overview",
  "risk_narrative": "Paragraph-level risk assessment",
  "annotations": [
    {{
      "check_id": "xx001",
      "resource_name": "tool_or_resource_name",
      "confidence": "confirmed",
      "confidence_score": 0.95,
      "reasoning": "Brief explanation",
      "false_positive_reason": null,
      "exploitability_note": "How exploitable in practice",
      "adjusted_severity": null,
      "additional_context": null
    }}
  ],
  "attack_chains": [
    {{
      "chain_id": "chain_001",
      "title": "Brief chain title",
      "description": "What this chain represents",
      "severity": "critical",
      "finding_check_ids": ["tp002", "iv001"],
      "finding_resource_names": ["tool_a", "tool_b"],
      "attack_narrative": "Step 1: ... Step 2: ...",
      "impact": "Business impact description",
      "owasp_mcp": ["MCP03:2025"]
    }}
  ],
  "gap_findings": [
    {{
      "title": "Brief title",
      "severity": "high",
      "resource_type": "tool",
      "resource_name": "name",
      "description": "Detailed description",
      "evidence": "Specific data from the snapshot",
      "remediation": "How to fix",
      "owasp_mcp": ["MCP03:2025"],
      "reasoning": "Why static checks missed this"
    }}
  ],
  "top_priorities": [
    "1. Most critical action",
    "2. Second priority"
  ]
}}

RULES:
1. Only annotate findings from the STATIC FINDINGS section below.
2. Only report gap_findings with CONCRETE evidence from the snapshot.
3. Do NOT invent theoretical risks without supporting data.
4. Confidence scores must reflect YOUR certainty, not the severity level.
5. Attack chains must connect at least 2 distinct findings.
6. OWASP MCP codes: MCP01 (Prompt Injection), MCP02 (Tool Misuse), \
MCP03 (Tool Poisoning), MCP04 (Privilege Escalation), MCP05 (Data \
Exfiltration), MCP06 (Indirect Prompt Injection), MCP07 (Unauthorized \
Access), MCP08 (Config Exposure), MCP09 (Logging Gaps), \
MCP10 (Supply Chain).
"""


def build_reasoning_system_prompt(
    num_findings: int,
    chunk_index: int = 0,
    total_chunks: int = 1,
) -> str:
    """Build the system prompt for a reasoning request.

    Parameters
    ----------
    num_findings:
        Total FAIL findings being sent for reasoning.
    chunk_index:
        Zero-based index of this chunk (for multi-chunk payloads).
    total_chunks:
        Total number of chunks in this reasoning pass.
    """
    if total_chunks > 1:
        chunk_context = (
            f"NOTE: This is chunk {chunk_index + 1} of {total_chunks}. "
            f"You are seeing a subset of the findings. Focus your "
            f"analysis on the findings provided in this chunk."
        )
    else:
        chunk_context = ""

    return REASONING_SYSTEM_PROMPT.format(
        num_findings=num_findings,
        chunk_context=chunk_context,
    )


def build_reasoning_user_payload(
    snapshot: ServerSnapshot,
    findings: list[Finding],
) -> str:
    """Build the user payload: server snapshot + compact findings.

    The snapshot is serialized using the existing ``build_analysis_payload``
    helper.  Findings are formatted compactly — only FAIL findings are
    included with their key fields.
    """
    # Section 1: Server snapshot (reuse existing serializer)
    snapshot_text = build_analysis_payload(
        server_name=snapshot.server_name,
        transport_type=snapshot.transport_type,
        tools=snapshot.tools,
        resources=snapshot.resources,
        prompts=snapshot.prompts,
        capabilities=snapshot.capabilities,
        config_raw=snapshot.config_raw,
    )

    # Section 2: Compact findings summary
    fail_findings = [f for f in findings if f.status == Status.FAIL]
    pass_count = sum(1 for f in findings if f.status == Status.PASS)
    error_count = sum(1 for f in findings if f.status == Status.ERROR)

    lines: list[str] = [
        "",
        "=" * 60,
        "STATIC FINDINGS",
        "=" * 60,
        f"Summary: {len(fail_findings)} failed, {pass_count} passed"
        f"{f', {error_count} errors' if error_count else ''}",
        "",
    ]

    for f in fail_findings:
        lines.append(f"[{f.severity.value.upper()}] {f.check_id}: {f.check_title}")
        lines.append(f"  Resource: {f.resource_type}/{f.resource_name}")
        # Truncate long details to save tokens
        detail = f.status_extended
        if len(detail) > 200:
            detail = detail[:197] + "..."
        lines.append(f"  Detail: {detail}")
        if f.evidence:
            evidence = f.evidence
            if len(evidence) > 150:
                evidence = evidence[:147] + "..."
            lines.append(f"  Evidence: {evidence}")
        if f.owasp_mcp:
            lines.append(f"  OWASP: {', '.join(f.owasp_mcp)}")
        lines.append("")

    return snapshot_text + "\n".join(lines)
