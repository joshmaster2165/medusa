"""Custom exception types for Medusa."""


class MedusaError(Exception):
    """Base exception for all Medusa errors."""


class ConnectionError(MedusaError):
    """Failed to connect to an MCP server."""


class ConfigError(MedusaError):
    """Invalid or missing configuration."""


class CheckError(MedusaError):
    """A check encountered an unexpected error during execution."""


class ReporterError(MedusaError):
    """Failed to generate a report."""


class AiApiError(MedusaError):
    """AI API request failed (Claude/proxy)."""


class AiResponseParseError(MedusaError):
    """AI returned an unparseable response."""


class CreditError(MedusaError):
    """Credit check or deduction failed."""


class InsufficientCreditsError(CreditError):
    """Not enough credits to complete the AI scan."""
