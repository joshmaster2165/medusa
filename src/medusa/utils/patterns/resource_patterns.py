"""Patterns for resource URI validation."""

from __future__ import annotations

# Standard URI schemes considered safe for MCP resources
STANDARD_URI_SCHEMES: set[str] = {
    "file",
    "https",
    "http",
    "data",
    "blob",
    "s3",
    "gs",
    "mcp",
    "ftp",
    "sftp",
    "ssh",
    "git",
    "postgres",
    "postgresql",
    "mysql",
    "redis",
    "mongodb",
    "sqlite",
}
