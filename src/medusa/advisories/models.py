"""Advisory data model for the Medusa Advisory Database."""

from __future__ import annotations

from pydantic import BaseModel


class Advisory(BaseModel):
    """A Medusa Advisory Database entry tracking a known MCP attack pattern."""

    id: str                           # MAD-2025-0001
    title: str
    severity: str                     # critical, high, medium, low
    description: str
    affected_tools_pattern: str       # Description of affected tool patterns
    attack_vector: str
    impact: str
    references: list[str] = []
    related_checks: list[str] = []    # Medusa check IDs
    owasp_mcp: list[str] = []         # OWASP MCP Top 10 IDs
    published_date: str               # ISO date
    cwe: list[str] = []               # CWE references
    tags: list[str] = []
