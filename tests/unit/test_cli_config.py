"""Tests for medusa.cli.config - user-level CLI configuration."""

from pathlib import Path
from unittest.mock import patch

from medusa.cli.config import (
    DEFAULT_DASHBOARD_URL,
    UserConfig,
    load_user_config,
    save_user_config,
)


# ── UserConfig defaults ─────────────────────────────────────────────────────


class TestUserConfig:
    def test_defaults(self):
        cfg = UserConfig()
        assert cfg.api_key is None
        assert cfg.dashboard_url == DEFAULT_DASHBOARD_URL

    def test_custom_values(self):
        cfg = UserConfig(api_key="sk-test", dashboard_url="https://custom.example.com")
        assert cfg.api_key == "sk-test"
        assert cfg.dashboard_url == "https://custom.example.com"

    def test_model_dump_excludes_none_api_key(self):
        cfg = UserConfig()
        dumped = cfg.model_dump(exclude_none=True)
        assert "api_key" not in dumped
        assert "dashboard_url" in dumped


# ── load / save roundtrip ───────────────────────────────────────────────────


class TestLoadSaveConfig:
    def test_load_returns_defaults_when_no_file(self, tmp_path: Path):
        fake_file = tmp_path / ".medusa" / "config.yaml"
        with patch("medusa.cli.config.CONFIG_FILE", fake_file):
            cfg = load_user_config()
        assert cfg.api_key is None
        assert cfg.dashboard_url == DEFAULT_DASHBOARD_URL

    def test_save_and_load_roundtrip(self, tmp_path: Path):
        fake_dir = tmp_path / ".medusa"
        fake_file = fake_dir / "config.yaml"
        with (
            patch("medusa.cli.config.CONFIG_DIR", fake_dir),
            patch("medusa.cli.config.CONFIG_FILE", fake_file),
        ):
            original = UserConfig(api_key="sk-round", dashboard_url="https://test.io/api")
            save_user_config(original)
            loaded = load_user_config()
        assert loaded.api_key == "sk-round"
        assert loaded.dashboard_url == "https://test.io/api"

    def test_save_creates_directory(self, tmp_path: Path):
        fake_dir = tmp_path / "nested" / ".medusa"
        fake_file = fake_dir / "config.yaml"
        with (
            patch("medusa.cli.config.CONFIG_DIR", fake_dir),
            patch("medusa.cli.config.CONFIG_FILE", fake_file),
        ):
            save_user_config(UserConfig(api_key="sk-dir"))
        assert fake_file.exists()

    def test_load_empty_file_returns_defaults(self, tmp_path: Path):
        fake_dir = tmp_path / ".medusa"
        fake_dir.mkdir()
        fake_file = fake_dir / "config.yaml"
        fake_file.write_text("")
        with patch("medusa.cli.config.CONFIG_FILE", fake_file):
            cfg = load_user_config()
        assert cfg.api_key is None

    def test_partial_update_preserves_other_fields(self, tmp_path: Path):
        fake_dir = tmp_path / ".medusa"
        fake_file = fake_dir / "config.yaml"
        with (
            patch("medusa.cli.config.CONFIG_DIR", fake_dir),
            patch("medusa.cli.config.CONFIG_FILE", fake_file),
        ):
            save_user_config(UserConfig(api_key="sk-first", dashboard_url="https://one.io"))
            # Load, change only the key, save again
            cfg = load_user_config()
            cfg.api_key = "sk-second"
            save_user_config(cfg)
            reloaded = load_user_config()
        assert reloaded.api_key == "sk-second"
        assert reloaded.dashboard_url == "https://one.io"
