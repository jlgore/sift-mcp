"""Tests for sift_mcp.tools.discovery."""

import pytest
from sift_mcp.catalog import clear_catalog_cache
from sift_mcp.manifest import clear_manifest_cache, load_manifest
from sift_mcp.tools.discovery import (
    ARTIFACT_ALIASES,
    check_tools,
    get_tool_help,
    list_available_tools,
    suggest_tools,
)


@pytest.fixture(autouse=True)
def clear_cache():
    clear_catalog_cache()
    clear_manifest_cache()
    yield
    clear_catalog_cache()
    clear_manifest_cache()


class TestListTools:
    def test_list_all(self):
        tools = list_available_tools()
        assert len(tools) >= 15
        names = [t["name"] for t in tools]
        assert "AmcacheParser" in names

    def test_list_by_category(self):
        tools = list_available_tools(category="zimmerman")
        assert len(tools) == 13
        assert all(t["category"] == "zimmerman" for t in tools)

    def test_availability_field(self):
        tools = list_available_tools()
        for t in tools:
            assert "available" in t
            assert isinstance(t["available"], bool)

    def test_catalog_entries_carry_scope_and_command(self):
        for t in list_available_tools():
            assert t["enriched"] is True
            assert t["command"]
            assert t["analysis_scope"] in {"offline", "network_offline", "live_network"}


class TestSiftManifest:
    def test_manifest_loads(self):
        manifest = load_manifest()
        assert len(manifest) > 100  # full SIFT install is large
        keys = set(manifest[0])
        assert {"command", "package", "install_source", "analysis_scope"} <= keys

    def test_no_denied_binaries_in_manifest(self):
        cmds = {m["command"] for m in load_manifest()}
        assert {"nc", "env", "kill", "shutdown"}.isdisjoint(cmds)


class TestIncludeUncataloged:
    def test_off_by_default(self):
        tools = list_available_tools()
        assert all(t["enriched"] for t in tools)
        assert all(t["category"] != "uncataloged" for t in tools)

    def test_include_uncataloged_adds_long_tail(self):
        base = list_available_tools()
        full = list_available_tools(include_uncataloged=True)
        assert len(full) > len(base)
        cmds = {t["command"] for t in full}
        # a libyal CLI tool that is in the manifest but not the curated catalog
        assert "esedbexport" in cmds
        assert any(not t["enriched"] for t in full)

    def test_no_catalog_duplicates(self):
        full = list_available_tools(include_uncataloged=True)
        cmds = [t["command"].lower() for t in full]
        assert len(cmds) == len(set(cmds))

    def test_live_network_excluded_by_default(self):
        full = list_available_tools(include_uncataloged=True)
        assert all(t["analysis_scope"] != "live_network" for t in full)

    def test_live_network_opt_in(self):
        full = list_available_tools(include_uncataloged=True, include_live_network=True)
        scopes = {t["analysis_scope"] for t in full}
        assert "live_network" in scopes

    def test_uncataloged_entry_shape(self):
        full = list_available_tools(include_uncataloged=True)
        unc = next(t for t in full if not t["enriched"])
        assert unc["fk_tool"] is None
        assert "available" in unc
        assert "install_source" in unc


class TestGetToolHelp:
    def test_known_tool(self):
        help_info = get_tool_help("AmcacheParser")
        assert help_info["name"] == "AmcacheParser"
        assert "caveats" in help_info
        assert len(help_info["caveats"]) >= 1

    def test_unknown_tool(self):
        result = get_tool_help("nonexistent_tool")
        assert "error" in result


class TestCheckTools:
    def test_check_specific(self):
        result = check_tools(["AmcacheParser", "PECmd"])
        assert "AmcacheParser" in result
        assert "PECmd" in result

    def test_check_all(self):
        result = check_tools()
        assert len(result) >= 15


class TestSuggestTools:
    def test_suggest_for_amcache(self):
        result = suggest_tools("amcache")
        assert isinstance(result, dict)
        assert "suggestions" in result
        assert len(result["suggestions"]) >= 1
        tool_names = [s.get("tool", "") for s in result["suggestions"]]
        assert "AmcacheParser" in tool_names

    def test_suggest_includes_corroboration(self):
        result = suggest_tools("amcache")
        assert "corroboration" in result
        assert "for_execution" in result["corroboration"]

    def test_suggest_unknown_artifact(self):
        result = suggest_tools("nonexistent_artifact")
        assert isinstance(result, dict)
        assert result.get("info") is not None or len(result.get("suggestions", [])) == 0

    def test_suggest_includes_discipline_reminder(self):
        result = suggest_tools("prefetch")
        assert "discipline_reminder" in result

    def test_suggest_includes_advisories(self):
        result = suggest_tools("prefetch")
        assert "advisories" in result
        assert len(result["advisories"]) >= 1

    def test_suggest_includes_cross_mcp_checks(self):
        result = suggest_tools("prefetch")
        assert "cross_mcp_checks" in result
        assert len(result["cross_mcp_checks"]) >= 1

    def test_alias_evtx(self):
        result = suggest_tools("evtx")
        assert isinstance(result, dict)
        assert len(result["suggestions"]) >= 1

    def test_alias_registry(self):
        result = suggest_tools("registry")
        assert isinstance(result, dict)
        assert len(result["suggestions"]) >= 1

    def test_alias_event_logs(self):
        result = suggest_tools("event_logs")
        assert isinstance(result, dict)
        assert len(result["suggestions"]) >= 1


class TestArtifactAliases:
    def test_aliases_defined(self):
        assert len(ARTIFACT_ALIASES) >= 8
        assert "evtx" in ARTIFACT_ALIASES
        assert "registry" in ARTIFACT_ALIASES

    def test_aliases_resolve_to_valid_artifacts(self):
        from forensic_knowledge import loader

        for alias, targets in ARTIFACT_ALIASES.items():
            for target in targets:
                art = loader.get_artifact(target)
                assert art is not None, (
                    f"Alias '{alias}' target '{target}' not found in FK"
                )
