"""User-level Medusa CLI configuration (~/.medusa/config.yaml)."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel

DEFAULT_DASHBOARD_URL = "https://app.medusa.security/api/v1/reports"
CONFIG_DIR = Path.home() / ".medusa"
CONFIG_FILE = CONFIG_DIR / "config.yaml"


class UserConfig(BaseModel):
    """Persistent user configuration for the Medusa CLI."""

    api_key: str | None = None
    dashboard_url: str = DEFAULT_DASHBOARD_URL


def load_user_config() -> UserConfig:
    """Load user config from ~/.medusa/config.yaml, or return defaults."""
    if CONFIG_FILE.exists():
        raw = yaml.safe_load(CONFIG_FILE.read_text())
        if raw:
            return UserConfig.model_validate(raw)
    return UserConfig()


def save_user_config(config: UserConfig) -> None:
    """Persist user config to ~/.medusa/config.yaml."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        yaml.dump(config.model_dump(exclude_none=True), default_flow_style=False)
    )
