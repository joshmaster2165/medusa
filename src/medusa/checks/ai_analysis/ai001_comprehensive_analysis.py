"""AI-001: Comprehensive AI-powered security analysis.

Uses Claude to perform deep semantic analysis of an MCP server's tools,
resources, prompts, and configuration — catching issues that static
pattern matching cannot detect.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

logger = logging.getLogger(__name__)


class AiComprehensiveAnalysisCheck(BaseCheck):
    """Comprehensive AI security analysis of an MCP server."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()

        # Import AI modules lazily so static-only scans never touch them
        try:
            from medusa.ai.client import get_client, get_credit_manager
        except Exception:
            # AI not configured — this check should have been filtered
            # out by the ScanEngine when ai_enabled=False.
            return []

        # ── Credit check ────────────────────────────────────────────
        try:
            credit_mgr = get_credit_manager()
            ok = await credit_mgr.deduct(
                check_id=meta.check_id,
                server_name=snapshot.server_name,
                scan_id="",  # Filled by caller if available
            )
            if not ok:
                return [
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.SKIPPED,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="server",
                        resource_name=snapshot.server_name,
                        status_extended=(
                            "Insufficient AI credits. "
                            "Purchase credits at your dashboard."
                        ),
                        remediation="Add credits to your account.",
                        owasp_mcp=meta.owasp_mcp,
                    )
                ]
        except Exception as e:
            logger.warning("Credit check failed: %s", e)
            # Continue anyway if credit system is unreachable
            # (graceful degradation)

        # ── Build analysis payload ──────────────────────────────────
        from medusa.ai.prompts import (
            COMPREHENSIVE_SYSTEM_PROMPT,
            build_analysis_payload,
        )

        payload = build_analysis_payload(
            server_name=snapshot.server_name,
            transport_type=snapshot.transport_type,
            tools=snapshot.tools,
            resources=snapshot.resources,
            prompts=snapshot.prompts,
            capabilities=snapshot.capabilities,
            config_raw=snapshot.config_raw,
        )

        # ── Call Claude ─────────────────────────────────────────────
        from medusa.ai.response_parser import parse_ai_response

        try:
            client = get_client()
            response = await client.analyze(
                COMPREHENSIVE_SYSTEM_PROMPT, payload
            )
        except Exception as e:
            logger.error("AI analysis failed: %s", e)
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.ERROR,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=f"AI analysis failed: {e}",
                    remediation=(
                        "Retry the scan. If the error persists, "
                        "check your API key with 'medusa settings'."
                    ),
                    owasp_mcp=meta.owasp_mcp,
                )
            ]

        # ── Parse response into Findings ────────────────────────────
        return parse_ai_response(
            response=response,
            meta=meta,
            server_name=snapshot.server_name,
            server_transport=snapshot.transport_type,
        )
