"""Parse Claude API responses into Medusa Finding objects."""

from __future__ import annotations

import logging

from medusa.core.models import CheckMetadata, Finding, Severity, Status

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
}

_VALID_RESOURCE_TYPES = {"tool", "resource", "prompt", "server"}


def parse_ai_response(
    response: dict,
    meta: CheckMetadata,
    server_name: str,
    server_transport: str,
    valid_check_ids: set[str] | None = None,
) -> list[Finding]:
    """Convert a Claude JSON response into a list of Finding objects.

    When *valid_check_ids* is provided (category-aware mode), each
    finding's ``check_id`` comes from Claude's response and is validated
    against the known static check IDs.  Unknown IDs are still accepted
    but logged as warnings.

    If the response is malformed, returns a single ERROR finding
    rather than crashing the scan.
    """
    findings_data = response.get("findings")
    if findings_data is None:
        logger.warning("AI response missing 'findings' key")
        return [
            _error_finding(
                meta,
                server_name,
                server_transport,
                "AI response missing 'findings' key",
            )
        ]

    if not isinstance(findings_data, list):
        logger.warning("AI response 'findings' is not a list")
        return [
            _error_finding(
                meta,
                server_name,
                server_transport,
                "AI response 'findings' is not a list",
            )
        ]

    if not findings_data:
        # No issues found — return a single PASS finding
        return [
            Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=server_name,
                server_transport=server_transport,
                resource_type="server",
                resource_name=server_name,
                status_extended=(
                    "AI analysis found no security issues."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]

    findings: list[Finding] = []
    for i, item in enumerate(findings_data):
        if not isinstance(item, dict):
            logger.warning("AI finding #%d is not a dict, skipping", i)
            continue

        try:
            finding = _parse_one_finding(
                item, meta, server_name, server_transport,
                valid_check_ids=valid_check_ids,
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse AI finding #%d: %s", i, e)
            continue

    # If all individual findings failed to parse, return an error
    if not findings and findings_data:
        return [
            _error_finding(
                meta,
                server_name,
                server_transport,
                "All AI findings failed to parse",
            )
        ]

    return findings


def _parse_one_finding(
    item: dict,
    meta: CheckMetadata,
    server_name: str,
    server_transport: str,
    valid_check_ids: set[str] | None = None,
) -> Finding:
    """Parse a single finding dict from Claude's response.

    In category-aware mode (*valid_check_ids* provided), the check_id
    is taken from Claude's response and validated. In legacy mode
    (no valid_check_ids), the check_id always comes from *meta*.
    """
    severity_str = item.get("severity", "medium").lower()
    severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

    resource_type = item.get("resource_type", "server").lower()
    if resource_type not in _VALID_RESOURCE_TYPES:
        resource_type = "server"

    resource_name = item.get("resource_name", server_name)
    if not resource_name:
        resource_name = server_name

    title = item.get("title", meta.title)
    status_extended = item.get("status_extended", "AI-detected issue")
    evidence = item.get("evidence")
    remediation = item.get("remediation", meta.remediation)

    owasp = item.get("owasp_mcp", meta.owasp_mcp)
    if not isinstance(owasp, list):
        owasp = meta.owasp_mcp

    # ── Resolve check_id ──────────────────────────────────────────
    if valid_check_ids is not None:
        # Category-aware mode: Claude provides the check_id
        claude_id = item.get("check_id", "").strip()
        if claude_id and claude_id in valid_check_ids:
            check_id = claude_id
        elif claude_id:
            # Accept Claude's ID but log a warning
            logger.warning(
                "AI returned unknown check_id '%s' "
                "(not in category's static checks)",
                claude_id,
            )
            check_id = claude_id
        else:
            # No check_id from Claude — fall back to AI check's own ID
            check_id = meta.check_id
    else:
        # Legacy mode: always use the AI check's ID
        check_id = meta.check_id

    # Ensure [AI] prefix on title
    if not title.startswith("[AI]"):
        title = f"[AI] {title}"

    return Finding(
        check_id=check_id,
        check_title=title,
        status=Status.FAIL,
        severity=severity,
        server_name=server_name,
        server_transport=server_transport,
        resource_type=resource_type,
        resource_name=resource_name,
        status_extended=status_extended,
        evidence=evidence,
        remediation=remediation,
        owasp_mcp=owasp,
    )


def _error_finding(
    meta: CheckMetadata,
    server_name: str,
    server_transport: str,
    detail: str,
) -> Finding:
    """Create an ERROR finding when AI response parsing fails."""
    return Finding(
        check_id=meta.check_id,
        check_title=meta.title,
        status=Status.ERROR,
        severity=meta.severity,
        server_name=server_name,
        server_transport=server_transport,
        resource_type="server",
        resource_name=server_name,
        status_extended=f"AI analysis error: {detail}",
        remediation="Retry the AI scan. If the issue persists, report a bug.",
        owasp_mcp=meta.owasp_mcp,
    )
