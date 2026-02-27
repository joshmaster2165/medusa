"""Tests for medusa.utils.config_parser - configuration loading and parsing."""

import pytest

from medusa.utils.config_parser import (
    MedusaConfig,
    _expand_env_vars,
    _process_env_vars,
    load_config,
)

# ── load_config ──────────────────────────────────────────────────────────────


class TestLoadConfig:
    def test_load_config_none_returns_default(self, tmp_path, monkeypatch):
        """load_config(None) with no config files in CWD returns defaults."""
        monkeypatch.chdir(tmp_path)
        config = load_config(None)
        assert isinstance(config, MedusaConfig)

    def test_load_config_nonexistent_path_raises_error(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/medusa.yaml")

    def test_load_config_from_yaml_file(self, tmp_path, monkeypatch):
        """Loading from a valid YAML file works."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "medusa.yaml"
        config_file.write_text(
            "version: '2'\ndiscovery:\n  auto_discover: false\nconnection:\n  timeout: 60\n"
        )
        config = load_config(str(config_file))
        assert config.version == "2"
        assert config.discovery.auto_discover is False
        assert config.connection.timeout == 60

    def test_load_config_empty_yaml_returns_default(self, tmp_path, monkeypatch):
        """An empty YAML file should return default config."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "medusa.yaml"
        config_file.write_text("")
        config = load_config(str(config_file))
        assert isinstance(config, MedusaConfig)
        assert config.version == "1"


# ── Default config values ────────────────────────────────────────────────────


class TestDefaultConfig:
    def test_auto_discover_default_true(self):
        config = MedusaConfig()
        assert config.discovery.auto_discover is True

    def test_version_default(self):
        config = MedusaConfig()
        assert config.version == "1"

    def test_output_formats_default_json(self):
        config = MedusaConfig()
        assert config.output.formats == ["json"]

    def test_output_directory_default(self):
        config = MedusaConfig()
        assert config.output.directory == "./medusa-reports"

    def test_connection_timeout_default(self):
        config = MedusaConfig()
        assert config.connection.timeout == 30

    def test_connection_retries_default(self):
        config = MedusaConfig()
        assert config.connection.retries == 2

    def test_connection_parallel_default(self):
        config = MedusaConfig()
        assert config.connection.parallel == 4

    def test_checks_min_severity_default(self):
        config = MedusaConfig()
        assert config.checks.min_severity == "low"

    def test_compliance_frameworks_default_empty(self):
        config = MedusaConfig()
        assert config.compliance.frameworks == []

    def test_output_include_evidence_default_true(self):
        config = MedusaConfig()
        assert config.output.include_evidence is True

    def test_output_include_passing_default_false(self):
        config = MedusaConfig()
        assert config.output.include_passing is False


# ── Environment variable expansion ───────────────────────────────────────────


class TestEnvVarExpansion:
    def test_expand_env_vars_with_set_var(self, monkeypatch):
        monkeypatch.setenv("MEDUSA_TEST_VALUE", "hello-world")
        result = _expand_env_vars("${MEDUSA_TEST_VALUE}")
        assert result == "hello-world"

    def test_expand_env_vars_no_var_returns_unchanged(self):
        result = _expand_env_vars("no variables here")
        assert result == "no variables here"

    def test_expand_env_vars_embedded(self, monkeypatch):
        monkeypatch.setenv("MEDUSA_HOST", "localhost")
        result = _expand_env_vars("http://${MEDUSA_HOST}:8080")
        assert result == "http://localhost:8080"

    def test_process_env_vars_dict(self, monkeypatch):
        monkeypatch.setenv("MEDUSA_KEY", "secret")
        data = {"key": "${MEDUSA_KEY}", "number": 42}
        result = _process_env_vars(data)
        assert result["key"] == "secret"
        assert result["number"] == 42

    def test_process_env_vars_list(self, monkeypatch):
        monkeypatch.setenv("MEDUSA_ITEM", "value")
        data = ["${MEDUSA_ITEM}", "plain"]
        result = _process_env_vars(data)
        assert result == ["value", "plain"]

    def test_process_env_vars_nested(self, monkeypatch):
        monkeypatch.setenv("MEDUSA_NESTED", "deep")
        data = {"outer": {"inner": "${MEDUSA_NESTED}"}}
        result = _process_env_vars(data)
        assert result["outer"]["inner"] == "deep"

    def test_load_config_expands_env_vars(self, tmp_path, monkeypatch):
        """Full integration: env vars in YAML are expanded during load."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("MEDUSA_REPORT_DIR", "/tmp/reports")
        config_file = tmp_path / "medusa.yaml"
        config_file.write_text("output:\n  directory: '${MEDUSA_REPORT_DIR}'\n")
        config = load_config(str(config_file))
        assert config.output.directory == "/tmp/reports"
