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
