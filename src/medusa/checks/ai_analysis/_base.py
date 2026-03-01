"""Base class for category-aware AI security checks.

Each of the 24 AI checks covers one static-check category. The base
class loads every static check in that category, builds a prompt
listing them all, sends the snapshot to Claude, and returns findings
that reference the *original* static check IDs (e.g. tp001, iv003).
"""

from __future__ import annotations

import logging
from abc import abstractmethod
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

logger = logging.getLogger(__name__)


def _first_sentence(text: str) -> str:
    """Extract the first sentence from a multi-sentence string."""
    text = text.strip().replace("\n", " ")
    for sep in (". ", ".\n"):
        idx = text.find(sep)
        if idx != -1:
            return text[: idx + 1]
    # No period found — return whole text, capped at 200 chars
    return text[:200]


class BaseAiCategoryCheck(BaseCheck):
    """AI check that mirrors all static checks within a single category.

    Subclasses implement two tiny methods:
    - ``_category()`` — the static-check category to cover
    - ``_meta_file()`` — stem of the ``.metadata.yaml`` sidecar

    Everything else — credit handling, prompt building, Claude calling,
    response parsing — lives here.
    """

    @abstractmethod
    def _category(self) -> str:
        """Return the static-check category this AI check covers."""

    @abstractmethod
    def _meta_file(self) -> str:
        """Return the metadata filename stem (without .metadata.yaml)."""

    # ── metadata ──────────────────────────────────────────────────────

    def metadata(self) -> CheckMetadata:
        meta_path = (
            Path(__file__).parent / f"{self._meta_file()}.metadata.yaml"
        )
        return CheckMetadata(**yaml.safe_load(meta_path.read_text()))

    # ── execute ───────────────────────────────────────────────────────

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()

        # Lazy imports so static-only scans never touch AI modules
        try:
            from medusa.ai.client import get_client
        except Exception:
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
                    status_extended=(
                        "AI client not configured. "
                        "Use --ai or --all to enable AI scanning."
                    ),
                    remediation="Run with --ai or --all flag.",
                    owasp_mcp=meta.owasp_mcp,
                )
            ]

        # NOTE: Credit deduction is handled once per scan in the CLI
        # (see _deduct_ai_scan_credit in main.py), not per-check.

        # ── Build category-specific prompt ────────────────────────────
        from medusa.ai.prompts import (
            CATEGORY_SYSTEM_PROMPT,
            build_analysis_payload,
        )

        check_list = self._build_check_list()
        category_prefix = self._get_category_prefix()

        system_prompt = CATEGORY_SYSTEM_PROMPT.format(
            check_list=check_list,
            category_prefix=category_prefix,
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

        # ── Call Claude ───────────────────────────────────────────────
        try:
            client = get_client()
            response = await client.analyze(system_prompt, payload)
        except Exception as e:
            logger.error(
                "AI analysis failed for %s: %s", meta.check_id, e
            )
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

        # ── Parse response ────────────────────────────────────────────
        from medusa.ai.response_parser import parse_ai_response

        valid_ids = self._get_valid_check_ids()

        # Log coverage if Claude reported which checks it evaluated
        self._log_coverage(response, valid_ids, meta.check_id)

        return parse_ai_response(
            response=response,
            meta=meta,
            server_name=snapshot.server_name,
            server_transport=snapshot.transport_type,
            valid_check_ids=valid_ids,
        )

    # ── helpers ───────────────────────────────────────────────────────

    def _build_check_list(self) -> str:
        """Build a prompt section listing every static check in this category.

        Each check includes:
        - ID and title
        - First sentence of description (what the check detects)
        - First sentence of risk_explanation (what to look for)
        - OWASP MCP codes
        """
        from medusa.core.registry import CheckRegistry

        registry = CheckRegistry()
        registry.discover_checks()
        checks = registry.get_checks(categories=[self._category()])
        static = [
            c
            for c in checks
            if not c.metadata().check_id.startswith("ai")
        ]

        lines = [
            f"CHECKS IN CATEGORY '{self._category()}' "
            f"({len(static)} checks) — evaluate ALL of them:",
        ]
        for c in static:
            m = c.metadata()
            desc = _first_sentence(m.description)
            risk = _first_sentence(m.risk_explanation)
            lines.append(f"- {m.check_id}: {m.title}")
            lines.append(f"  What: {desc}")
            if risk and risk != desc:
                lines.append(f"  Look for: {risk}")
            if m.owasp_mcp:
                lines.append(f"  OWASP: {', '.join(m.owasp_mcp)}")
        return "\n".join(lines)

    def _log_coverage(
        self,
        response: dict,
        valid_ids: set[str],
        ai_check_id: str,
    ) -> None:
        """Log coverage stats from Claude's checks_evaluated field."""
        evaluated = response.get("checks_evaluated")
        if not isinstance(evaluated, list):
            return

        evaluated_set = set(evaluated)
        total = len(valid_ids)
        covered = len(evaluated_set & valid_ids)

        if total > 0:
            pct = (covered / total) * 100
            if pct < 80:
                logger.warning(
                    "%s: Claude evaluated %d/%d checks (%.0f%%) — "
                    "below 80%% coverage threshold",
                    ai_check_id,
                    covered,
                    total,
                    pct,
                )
            else:
                logger.info(
                    "%s: Claude evaluated %d/%d checks (%.0f%%)",
                    ai_check_id,
                    covered,
                    total,
                    pct,
                )

    def _get_valid_check_ids(self) -> set[str]:
        """Return the set of valid static check IDs for this category."""
        from medusa.core.registry import CheckRegistry

        registry = CheckRegistry()
        registry.discover_checks()
        checks = registry.get_checks(categories=[self._category()])
        return {
            c.metadata().check_id
            for c in checks
            if not c.metadata().check_id.startswith("ai")
        }

    def _get_category_prefix(self) -> str:
        """Extract the check_id prefix for this category (e.g. 'tp', 'iv')."""
        valid_ids = self._get_valid_check_ids()
        if valid_ids:
            # All IDs in a category share the same prefix
            sample = next(iter(sorted(valid_ids)))
            # Strip trailing digits to get prefix
            prefix = sample.rstrip("0123456789")
            return prefix
        return self._category()[:3]
