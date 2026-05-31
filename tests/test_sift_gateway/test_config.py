"""Tests for config loading and env var interpolation."""

import pytest
from sift_gateway.config import (
    _interpolate_env,
    _walk_and_interpolate,
    apply_security_layers,
    load_config,
)

# --- _interpolate_env ---


class TestInterpolateEnv:
    def test_simple_var(self, monkeypatch):
        monkeypatch.setenv("MY_VAR", "hello")
        assert _interpolate_env("${MY_VAR}") == "hello"

    def test_var_in_string(self, monkeypatch):
        monkeypatch.setenv("HOST", "localhost")
        assert _interpolate_env("http://${HOST}:8080") == "http://localhost:8080"

    def test_missing_var_empty(self):
        result = _interpolate_env("${SURELY_NOT_SET_12345}")
        assert result == ""

    def test_multiple_vars(self, monkeypatch):
        monkeypatch.setenv("A", "1")
        monkeypatch.setenv("B", "2")
        assert _interpolate_env("${A}-${B}") == "1-2"

    def test_no_vars(self):
        assert _interpolate_env("plain string") == "plain string"


# --- _walk_and_interpolate ---


class TestWalkAndInterpolate:
    def test_nested_dict(self, monkeypatch):
        monkeypatch.setenv("PORT", "9090")
        data = {"server": {"port": "${PORT}", "host": "localhost"}}
        result = _walk_and_interpolate(data)
        assert result == {"server": {"port": "9090", "host": "localhost"}}

    def test_list(self, monkeypatch):
        monkeypatch.setenv("ARG", "foo")
        data = ["${ARG}", "bar"]
        result = _walk_and_interpolate(data)
        assert result == ["foo", "bar"]

    def test_non_string_passthrough(self):
        assert _walk_and_interpolate(42) == 42
        assert _walk_and_interpolate(True) is True
        assert _walk_and_interpolate(None) is None


# --- load_config ---


class TestLoadConfig:
    def test_load_valid_yaml(self, tmp_path):
        config_file = tmp_path / "test.yaml"
        config_file.write_text("gateway:\n  port: 4508\n")
        result = load_config(str(config_file))
        assert result["gateway"]["port"] == 4508

    def test_load_with_env_interpolation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GW_PORT", "9999")
        config_file = tmp_path / "test.yaml"
        config_file.write_text("gateway:\n  port_str: '${GW_PORT}'\n")
        result = load_config(str(config_file))
        assert result["gateway"]["port_str"] == "9999"

    def test_missing_config_raises(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/config.yaml")

    def test_empty_yaml_returns_empty_dict(self, tmp_path):
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")
        result = load_config(str(config_file))
        assert result == {}

    def test_full_config_structure(self, tmp_path):
        config_file = tmp_path / "full.yaml"
        config_file.write_text("""
gateway:
  host: "0.0.0.0"
  port: 4508
api_keys:
  key1:
    analyst: "steve"
    role: "lead"
backends:
  test-mcp:
    type: stdio
    command: python
    args: ["-m", "test_mcp"]
    enabled: true
""")
        result = load_config(str(config_file))
        assert result["gateway"]["host"] == "0.0.0.0"
        assert result["api_keys"]["key1"]["analyst"] == "steve"
        assert result["backends"]["test-mcp"]["type"] == "stdio"


# --- apply_security_layers (PRD §7 → SIFT_* env translation) ---


def _sift_backend(env=None):
    """A minimal stdio backend config that runs sift_mcp."""
    backend = {"type": "stdio", "command": "python", "args": ["-m", "sift_mcp"]}
    if env is not None:
        backend["env"] = env
    return {"backends": {"sift-mcp": backend}}


class TestApplySecurityLayers:
    def test_policy_engine_enabled_translates_to_env(self):
        config = _sift_backend()
        config["policy_engine"] = {"enabled": True}
        apply_security_layers(config)
        assert config["backends"]["sift-mcp"]["env"]["SIFT_POLICY_ENGINE"] == "1"

    def test_policy_engine_disabled_translates_to_zero(self):
        config = _sift_backend()
        config["policy_engine"] = {"enabled": False}
        apply_security_layers(config)
        assert config["backends"]["sift-mcp"]["env"]["SIFT_POLICY_ENGINE"] == "0"

    def test_sandbox_section_translates_all_fields(self):
        config = _sift_backend()
        config["sandbox"] = {
            "enabled": True,
            "profile": "strict",
            "bwrap_path": "/usr/bin/bwrap",
        }
        apply_security_layers(config)
        env = config["backends"]["sift-mcp"]["env"]
        assert env["SIFT_SANDBOX"] == "1"
        assert env["SIFT_SANDBOX_PROFILE"] == "strict"
        assert env["SIFT_BWRAP_PATH"] == "/usr/bin/bwrap"

    def test_paths_translate_when_present(self):
        config = _sift_backend()
        config["policy_engine"] = {
            "enabled": True,
            "opa_path": "/opt/opa",
            "security_yaml": "/etc/security.yaml",
        }
        apply_security_layers(config)
        env = config["backends"]["sift-mcp"]["env"]
        assert env["SIFT_OPA_PATH"] == "/opt/opa"
        assert env["SIFT_SECURITY_YAML"] == "/etc/security.yaml"

    def test_empty_string_value_skipped(self):
        # An unset ${VAR} interpolates to "" — must not clobber SiftConfig's
        # own fallback resolution.
        config = _sift_backend()
        config["policy_engine"] = {"enabled": True, "opa_path": ""}
        apply_security_layers(config)
        assert "SIFT_OPA_PATH" not in config["backends"]["sift-mcp"]["env"]

    def test_explicit_backend_env_wins(self):
        config = _sift_backend(env={"SIFT_POLICY_ENGINE": "0"})
        config["policy_engine"] = {"enabled": True}
        apply_security_layers(config)
        assert config["backends"]["sift-mcp"]["env"]["SIFT_POLICY_ENGINE"] == "0"

    def test_non_sift_backend_untouched(self):
        config = {
            "backends": {
                "other-mcp": {"type": "stdio", "command": "python", "args": ["-m", "other"]}
            },
            "policy_engine": {"enabled": True},
        }
        apply_security_layers(config)
        assert "env" not in config["backends"]["other-mcp"]

    def test_no_sections_is_noop(self):
        config = _sift_backend()
        apply_security_layers(config)
        assert "env" not in config["backends"]["sift-mcp"]

    def test_load_config_applies_translation(self, tmp_path):
        config_file = tmp_path / "gw.yaml"
        config_file.write_text(
            "policy_engine:\n"
            "  enabled: true\n"
            "sandbox:\n"
            "  enabled: true\n"
            "  profile: default\n"
            "backends:\n"
            "  sift-mcp:\n"
            "    type: stdio\n"
            "    command: python\n"
            "    args: ['-m', 'sift_mcp']\n"
        )
        result = load_config(str(config_file))
        env = result["backends"]["sift-mcp"]["env"]
        assert env["SIFT_POLICY_ENGINE"] == "1"
        assert env["SIFT_SANDBOX"] == "1"
        assert env["SIFT_SANDBOX_PROFILE"] == "default"
