"""Configuration file parser for Medusa scan configuration."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ServerConfig(BaseModel):
    """Configuration for a single MCP server to scan."""

    name: str
    transport: str = "stdio"  # "stdio" | "http"
    command: str | None = None
    args: list[str] = []
    env: dict[str, str] = {}
    url: str | None = None
    headers: dict[str, str] = {}


class DiscoveryConfig(BaseModel):
    """Server discovery configuration."""

    auto_discover: bool = True
    config_files: list[str] = []
    servers: list[ServerConfig] = []


class ChecksConfig(BaseModel):
    """Check selection configuration."""

    include: list[str] = []
    exclude: list[str] = []
    categories: list[str] = []
    min_severity: str = "low"


class ScoringConfig(BaseModel):
    """Scoring configuration."""

    fail_threshold: str = "high"
    max_findings: int = 0


class OutputConfig(BaseModel):
    """Output configuration."""

    formats: list[str] = Field(default_factory=lambda: ["json"])
    directory: str = "./medusa-reports"
    include_evidence: bool = True
    include_passing: bool = False


class ComplianceConfig(BaseModel):
    """Compliance framework configuration."""

    frameworks: list[str] = []


class ConnectionConfig(BaseModel):
    """Connection settings."""

    timeout: int = 30
    retries: int = 2
    parallel: int = 4


class MedusaConfig(BaseModel):
    """Top-level Medusa configuration."""

    version: str = "1"
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    checks: ChecksConfig = Field(default_factory=ChecksConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    connection: ConnectionConfig = Field(default_factory=ConnectionConfig)


def _expand_env_vars(value: str) -> str:
    """Expand ${ENV_VAR} references in string values."""
    if "${" not in value:
        return value
    return os.path.expandvars(value)


def _process_env_vars(data: dict | list | str) -> dict | list | str:
    """Recursively expand environment variables in config values."""
    if isinstance(data, dict):
        return {k: _process_env_vars(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_process_env_vars(item) for item in data]
    if isinstance(data, str):
        return _expand_env_vars(data)
    return data


def load_config(config_path: str | None = None) -> MedusaConfig:
    """Load Medusa configuration from a YAML file.

    Searches for config files in this order:
    1. Explicit path if provided
    2. ./medusa.yaml
    3. ./medusa.yml
    4. ./.medusa.yaml
    5. Default config (no file)
    """
    search_paths = [
        Path("medusa.yaml"),
        Path("medusa.yml"),
        Path(".medusa.yaml"),
    ]

    if config_path:
        target = Path(config_path)
        if not target.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        search_paths = [target]

    for path in search_paths:
        if path.exists():
            raw = yaml.safe_load(path.read_text())
            if raw is None:
                return MedusaConfig()
            processed = _process_env_vars(raw)
            return MedusaConfig.model_validate(processed)

    # No config file found — use defaults
    return MedusaConfig()
