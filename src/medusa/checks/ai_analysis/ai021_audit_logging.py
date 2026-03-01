"""AI-021: Audit Logging Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiAuditLoggingCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all audit_logging static checks."""

    def _category(self) -> str:
        return "audit_logging"

    def _meta_file(self) -> str:
        return "ai021_audit_logging"
