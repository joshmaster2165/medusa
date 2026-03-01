"""AI-009: Session Management Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiSessionManagementCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all session_management static checks."""

    def _category(self) -> str:
        return "session_management"

    def _meta_file(self) -> str:
        return "ai009_session_management"
