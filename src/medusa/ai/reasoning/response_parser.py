"""Parse Claude's reasoning response into structured models.

Handles malformed JSON gracefully — partial results are returned
rather than raising exceptions.
"""

from __future__ import annotations

import logging

from medusa.ai.reasoning.models import (
    AttackChain,
    Confidence,
    FalsePositiveReason,
    FindingAnnotation,
    GapFinding,
    ReasoningResult,
)

logger = logging.getLogger(__name__)

# Valid values for validation
_VALID_CONFIDENCES = {c.value for c in Confidence}
_VALID_FP_REASONS = {r.value for r in FalsePositiveReason}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def parse_reasoning_response(
    data: dict,
    server_name: str,
) -> ReasoningResult:
    """Parse Claude's reasoning JSON into a ReasoningResult.

    Tolerant of missing or malformed fields — extracts as much
    structured data as possible.

    Parameters
    ----------
    data:
        The parsed JSON dict from Claude's response.
    server_name:
        The server being analyzed (for the result envelope).
    """
    annotations = _parse_annotations(data.get("annotations", []))
    attack_chains = _parse_attack_chains(data.get("attack_chains", []))
    gap_findings = _parse_gap_findings(data.get("gap_findings", []))

    return ReasoningResult(
        server_name=server_name,
        annotations=annotations,
        attack_chains=attack_chains,
        gap_findings=gap_findings,
        executive_summary=str(data.get("executive_summary", "")),
        risk_narrative=str(data.get("risk_narrative", "")),
        top_priorities=_parse_string_list(
            data.get("top_priorities", [])
        ),
    )


def _parse_annotations(raw: list) -> list[FindingAnnotation]:
    """Parse annotation entries, skipping malformed ones."""
    annotations: list[FindingAnnotation] = []
    if not isinstance(raw, list):
        logger.warning("annotations is not a list, skipping")
        return annotations

    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            # Validate and clamp confidence_score
            score = float(entry.get("confidence_score", 0.5))
            score = max(0.0, min(1.0, score))

            # Validate confidence value
            confidence_val = str(
                entry.get("confidence", "uncertain")
            ).lower()
            if confidence_val not in _VALID_CONFIDENCES:
                confidence_val = "uncertain"

            # Validate false positive reason
            fp_reason = entry.get("false_positive_reason")
            if fp_reason and str(fp_reason).lower() in _VALID_FP_REASONS:
                fp_reason = str(fp_reason).lower()
            else:
                fp_reason = None

            # Validate adjusted severity
            adj_sev = entry.get("adjusted_severity")
            if adj_sev and str(adj_sev).lower() in _VALID_SEVERITIES:
                adj_sev = str(adj_sev).lower()
            else:
                adj_sev = None

            annotations.append(
                FindingAnnotation(
                    check_id=str(entry.get("check_id", "")),
                    resource_name=str(
                        entry.get("resource_name", "")
                    ),
                    confidence=Confidence(confidence_val),
                    confidence_score=score,
                    reasoning=str(entry.get("reasoning", "")),
                    false_positive_reason=(
                        FalsePositiveReason(fp_reason)
                        if fp_reason
                        else None
                    ),
                    exploitability_note=entry.get(
                        "exploitability_note"
                    ),
                    adjusted_severity=adj_sev,
                    additional_context=entry.get(
                        "additional_context"
                    ),
                )
            )
        except (ValueError, TypeError) as e:
            logger.warning("Skipping malformed annotation: %s", e)
            continue

    return annotations


def _parse_attack_chains(raw: list) -> list[AttackChain]:
    """Parse attack chain entries, skipping malformed ones."""
    chains: list[AttackChain] = []
    if not isinstance(raw, list):
        logger.warning("attack_chains is not a list, skipping")
        return chains

    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            severity = str(entry.get("severity", "medium")).lower()
            if severity not in _VALID_SEVERITIES:
                severity = "medium"

            chains.append(
                AttackChain(
                    chain_id=str(
                        entry.get("chain_id", f"chain_{len(chains):03d}")
                    ),
                    title=str(entry.get("title", "Unnamed Chain")),
                    description=str(entry.get("description", "")),
                    severity=severity,
                    finding_check_ids=_parse_string_list(
                        entry.get("finding_check_ids", [])
                    ),
                    finding_resource_names=_parse_string_list(
                        entry.get("finding_resource_names", [])
                    ),
                    attack_narrative=str(
                        entry.get("attack_narrative", "")
                    ),
                    impact=str(entry.get("impact", "")),
                    owasp_mcp=_parse_string_list(
                        entry.get("owasp_mcp", [])
                    ),
                )
            )
        except (ValueError, TypeError) as e:
            logger.warning("Skipping malformed attack chain: %s", e)
            continue

    return chains


def _parse_gap_findings(raw: list) -> list[GapFinding]:
    """Parse gap finding entries, skipping malformed ones."""
    gaps: list[GapFinding] = []
    if not isinstance(raw, list):
        logger.warning("gap_findings is not a list, skipping")
        return gaps

    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            severity = str(entry.get("severity", "medium")).lower()
            if severity not in _VALID_SEVERITIES:
                severity = "medium"

            gaps.append(
                GapFinding(
                    title=str(entry.get("title", "Untitled Gap")),
                    severity=severity,
                    resource_type=str(
                        entry.get("resource_type", "server")
                    ),
                    resource_name=str(
                        entry.get("resource_name", "unknown")
                    ),
                    description=str(entry.get("description", "")),
                    evidence=str(entry.get("evidence", "")),
                    remediation=str(entry.get("remediation", "")),
                    owasp_mcp=_parse_string_list(
                        entry.get("owasp_mcp", [])
                    ),
                    reasoning=str(entry.get("reasoning", "")),
                )
            )
        except (ValueError, TypeError) as e:
            logger.warning("Skipping malformed gap finding: %s", e)
            continue

    return gaps


def _parse_string_list(raw: object) -> list[str]:
    """Safely parse a list of strings from potentially malformed data."""
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if item is not None]
