"""AI-018: Secrets Management Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiSecretsManagementCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all secrets_management static checks."""

    def _category(self) -> str:
        return "secrets_management"

    def _meta_file(self) -> str:
        return "ai018_secrets_management"
