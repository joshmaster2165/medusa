"""AI-005: Privilege Scope Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiPrivilegeScopeCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all privilege_scope static checks."""

    def _category(self) -> str:
        return "privilege_scope"

    def _meta_file(self) -> str:
        return "ai005_privilege_scope"
