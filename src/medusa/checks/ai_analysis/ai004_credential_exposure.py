"""AI-004: Credential Exposure Analysis."""

from __future__ import annotations

from medusa.checks.ai_analysis._base import BaseAiCategoryCheck


class AiCredentialExposureCheck(BaseAiCategoryCheck):
    """AI analysis mirroring all credential_exposure static checks."""

    def _category(self) -> str:
        return "credential_exposure"

    def _meta_file(self) -> str:
        return "ai004_credential_exposure"
