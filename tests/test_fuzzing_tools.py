# ---------------------------------------------------------------------------
# Permutation tests
# ---------------------------------------------------------------------------

def test_permutation_generates_suffix_variants():
    from workers.fuzzing_worker.permutation import generate_permutations
    results = generate_permutations(["dev"], "target.com")
    assert "dev-api.target.com" in results
    assert "dev-staging.target.com" in results

def test_permutation_generates_prefix_variants():
    from workers.fuzzing_worker.permutation import generate_permutations
    results = generate_permutations(["api"], "target.com")
    assert "v1.api.target.com" in results
    assert "v2.api.target.com" in results

def test_permutation_swaps_separators():
    from workers.fuzzing_worker.permutation import generate_permutations
    results = generate_permutations(["dev-api"], "target.com")
    assert "dev.api.target.com" in results

def test_permutation_dedup_against_existing():
    from workers.fuzzing_worker.permutation import generate_permutations
    results = generate_permutations(
        ["dev"], "target.com", existing={"dev-api.target.com"},
    )
    assert "dev-api.target.com" not in results
    assert "dev-staging.target.com" in results

def test_permutation_extracts_prefix():
    from workers.fuzzing_worker.permutation import extract_prefix
    assert extract_prefix("dev.target.com", "target.com") == "dev"
    assert extract_prefix("api.staging.target.com", "target.com") == "api.staging"
    assert extract_prefix("target.com", "target.com") is None


# ---------------------------------------------------------------------------
# Sensitive pattern tests
# ---------------------------------------------------------------------------

def test_sensitive_match_env_file():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/.env")
    assert result is not None
    assert result["severity"] == "critical"
    assert result["category"] == "credentials_keys"

def test_sensitive_match_git_config():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/.git/config")
    assert result is not None
    assert result["severity"] == "high"
    assert result["category"] == "source_control"

def test_sensitive_match_backup_file():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/index.php.bak")
    assert result is not None
    assert result["severity"] == "medium"

def test_sensitive_no_match():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/about")
    assert result is None

def test_sensitive_match_sql_dump():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/backup.sql")
    assert result is not None
    assert result["severity"] == "critical"

def test_sensitive_match_vim_swap():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/.index.php.swp")
    assert result is not None
    assert result["severity"] == "medium"


# ---------------------------------------------------------------------------
# FfufTool tests
# ---------------------------------------------------------------------------

import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

SAMPLE_FFUF_OUTPUT = json.dumps({
    "results": [
        {"input": {"FUZZ": "admin"}, "status": 200, "length": 1234, "url": "https://acme.com/admin"},
        {"input": {"FUZZ": "backup"}, "status": 301, "length": 0, "url": "https://acme.com/backup"},
        {"input": {"FUZZ": ".env"}, "status": 200, "length": 89, "url": "https://acme.com/.env"},
        {"input": {"FUZZ": "secret"}, "status": 403, "length": 199, "url": "https://acme.com/secret"},
    ]
})


@pytest.mark.anyio
async def test_ffuf_tool_parses_json_output():
    from workers.fuzzing_worker.tools.ffuf_tool import FfufTool
    tool = FfufTool()
    results = tool.parse_output(SAMPLE_FFUF_OUTPUT)
    assert len(results) == 4
    assert results[0]["url"] == "https://acme.com/admin"
    assert results[0]["status"] == 200


@pytest.mark.anyio
async def test_ffuf_tool_builds_command_with_headers():
    from workers.fuzzing_worker.tools.ffuf_tool import FfufTool
    tool = FfufTool()
    cmd = tool.build_command(
        url="https://acme.com/FUZZ",
        wordlist="/app/wordlists/common.txt",
        rate_limit=50,
        headers={"Authorization": "Bearer tok"},
        output_file="/tmp/ffuf.json",
    )
    assert "ffuf" in cmd
    assert "-rate" in cmd
    assert "50" in cmd
    assert "-H" in cmd
    assert "Authorization: Bearer tok" in cmd


@pytest.mark.anyio
async def test_ffuf_tool_skips_on_cooldown():
    from workers.fuzzing_worker.tools.ffuf_tool import FfufTool
    tool = FfufTool()
    scope_mgr = MagicMock()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=scope_mgr, target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


@pytest.mark.anyio
async def test_ffuf_tool_execute_saves_assets():
    from workers.fuzzing_worker.tools.ffuf_tool import FfufTool
    tool = FfufTool()
    scope_mgr = MagicMock()
    target = MagicMock(target_profile={"rate_limit": 50})

    fake_tmp = MagicMock()
    fake_tmp.__enter__ = MagicMock(return_value=fake_tmp)
    fake_tmp.__exit__ = MagicMock(return_value=False)
    fake_tmp.name = "/tmp/_ffuf_test_nonexistent.json"

    with (
        patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=False),
        patch.object(tool, "_get_live_urls", new_callable=AsyncMock, return_value=[(1, "acme.com")]),
        patch.object(tool, "run_subprocess", new_callable=AsyncMock, return_value=SAMPLE_FFUF_OUTPUT),
        patch.object(tool, "_save_asset", new_callable=AsyncMock, return_value=10),
        patch.object(tool, "_save_vulnerability", new_callable=AsyncMock, return_value=1),
        patch.object(tool, "update_tool_state", new_callable=AsyncMock),
        patch("workers.fuzzing_worker.tools.ffuf_tool.tempfile.NamedTemporaryFile", return_value=fake_tmp),
    ):
        result = await tool.execute(
            target=target, scope_manager=scope_mgr,
            target_id=1, container_name="test", headers={},
        )

        assert result["found"] >= 1
        assert tool._save_asset.await_count >= 1


# ---------------------------------------------------------------------------
# ExtensionFuzzTool tests
# ---------------------------------------------------------------------------

def test_extension_fuzz_filters_dynamic_files():
    from workers.fuzzing_worker.tools.extension_fuzz_tool import ExtensionFuzzTool
    tool = ExtensionFuzzTool()
    files = [
        "https://acme.com/index.php",
        "https://acme.com/logo.png",
        "https://acme.com/style.css",
        "https://acme.com/config.json",
        "https://acme.com/admin",
    ]
    dynamic = tool.filter_dynamic_files(files)
    assert "https://acme.com/index.php" in dynamic
    assert "https://acme.com/config.json" in dynamic
    assert "https://acme.com/logo.png" not in dynamic
    assert "https://acme.com/style.css" not in dynamic
    assert "https://acme.com/admin" not in dynamic


def test_extension_fuzz_generates_variants():
    from workers.fuzzing_worker.tools.extension_fuzz_tool import ExtensionFuzzTool
    tool = ExtensionFuzzTool()
    variants = tool.generate_variants("https://acme.com/index.php")
    assert "https://acme.com/index.php.bak" in variants
    assert "https://acme.com/index.php.old" in variants
    assert "https://acme.com/.index.php.swp" in variants
    assert "https://acme.com/index.php~" in variants


# ---------------------------------------------------------------------------
# FeroxbusterTool tests
# ---------------------------------------------------------------------------

SAMPLE_FEROX_LINES = "\n".join([
    json.dumps({"url": "https://acme.com/admin/config", "status": 200, "content_length": 500}),
    json.dumps({"url": "https://acme.com/admin/users", "status": 200, "content_length": 1200}),
    json.dumps({"url": "https://acme.com/admin/.htaccess", "status": 403, "content_length": 50}),
])


@pytest.mark.anyio
async def test_feroxbuster_parses_jsonl_output():
    from workers.fuzzing_worker.tools.feroxbuster_tool import FeroxbusterTool
    tool = FeroxbusterTool()
    results = tool.parse_output(SAMPLE_FEROX_LINES)
    assert len(results) == 3
    assert results[0]["url"] == "https://acme.com/admin/config"


@pytest.mark.anyio
async def test_feroxbuster_builds_command():
    from workers.fuzzing_worker.tools.feroxbuster_tool import FeroxbusterTool
    tool = FeroxbusterTool()
    cmd = tool.build_command(
        url="https://acme.com/admin/",
        wordlist="/app/wordlists/common.txt",
        rate_limit=30,
        headers={"X-Custom": "val"},
        output_file="/tmp/ferox.json",
    )
    assert "feroxbuster" in cmd
    assert "--rate-limit" in cmd
    assert "30" in cmd


@pytest.mark.anyio
async def test_feroxbuster_execute_uses_discovered_dirs():
    import os as _os
    from workers.fuzzing_worker.tools.feroxbuster_tool import FeroxbusterTool
    tool = FeroxbusterTool()
    scope_mgr = MagicMock()
    target = MagicMock(target_profile={"rate_limit": 50})

    async def _fake_subprocess(cmd):
        """Write sample JSONL into the output file feroxbuster would create."""
        # The -o flag is followed by the output path in the command list
        out_idx = cmd.index("-o") + 1
        with open(cmd[out_idx], "w") as fh:
            fh.write(SAMPLE_FEROX_LINES)
        return ""

    with (
        patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=False),
        patch.object(tool, "run_subprocess", side_effect=_fake_subprocess),
        patch.object(tool, "_save_asset", new_callable=AsyncMock, return_value=10),
        patch.object(tool, "_save_vulnerability", new_callable=AsyncMock, return_value=1),
        patch.object(tool, "update_tool_state", new_callable=AsyncMock),
    ):
        result = await tool.execute(
            target=target, scope_manager=scope_mgr,
            target_id=1, container_name="test", headers={},
            discovered_dirs=["https://acme.com/admin/"],
        )

    assert result["found"] >= 1


# ---------------------------------------------------------------------------
# VhostFuzzTool tests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_vhost_fuzz_builds_command_per_ffuf_docs():
    from workers.fuzzing_worker.tools.vhost_fuzz_tool import VhostFuzzTool
    tool = VhostFuzzTool()
    cmd = tool.build_command(
        ip="93.184.216.34", base_domain="acme.com",
        wordlist="/tmp/vhost-wl.txt", rate_limit=50,
        baseline_size=1234, headers={}, output_file="/tmp/vhost.json",
    )
    assert "ffuf" in cmd
    assert "-H" in cmd
    host_idx = cmd.index("-H") + 1
    assert "FUZZ.acme.com" in cmd[host_idx]
    assert "-fs" in cmd
    assert "1234" in cmd


@pytest.mark.anyio
async def test_vhost_fuzz_builds_combined_wordlist():
    from workers.fuzzing_worker.tools.vhost_fuzz_tool import VhostFuzzTool
    tool = VhostFuzzTool()
    existing_prefixes = ["dev", "staging"]
    combined = tool.build_wordlist(existing_prefixes)
    assert "dev" in combined
    assert "staging" in combined
    assert len(combined) == len(set(combined))


# ---------------------------------------------------------------------------
# ArjunTool tests
# ---------------------------------------------------------------------------

SAMPLE_ARJUN_OUTPUT = json.dumps({
    "https://acme.com/api/users": {
        "GET": ["id", "debug", "admin"],
        "POST": ["token"],
    }
})

HIGH_VALUE_PARAMS = {"debug", "admin", "test", "load_config", "proxy",
                     "callback", "token", "secret"}


@pytest.mark.anyio
async def test_arjun_parses_json_output():
    from workers.fuzzing_worker.tools.arjun_tool import ArjunTool
    tool = ArjunTool()
    results = tool.parse_output(SAMPLE_ARJUN_OUTPUT)
    assert len(results) == 4
    names = {r["param_name"] for r in results}
    assert "debug" in names
    assert "token" in names


@pytest.mark.anyio
async def test_arjun_builds_command():
    from workers.fuzzing_worker.tools.arjun_tool import ArjunTool
    tool = ArjunTool()
    cmd = tool.build_command(
        url="https://acme.com/api", rate_limit=100,
        headers={"Auth": "Bearer tok"}, output_file="/tmp/arjun.json",
    )
    assert "arjun" in cmd
    assert "--stable" in cmd
    assert "--delay" in cmd


@pytest.mark.anyio
async def test_arjun_flags_high_value_params():
    from workers.fuzzing_worker.tools.arjun_tool import ArjunTool
    tool = ArjunTool()
    results = tool.parse_output(SAMPLE_ARJUN_OUTPUT)
    high_value = [r for r in results if r["param_name"] in HIGH_VALUE_PARAMS]
    assert len(high_value) >= 2


# ---------------------------------------------------------------------------
# HeaderFuzzTool tests
# ---------------------------------------------------------------------------

def test_header_fuzz_injection_headers_defined():
    from workers.fuzzing_worker.tools.header_fuzz_tool import INJECTION_HEADERS
    assert len(INJECTION_HEADERS) >= 5
    names = {h["name"] for h in INJECTION_HEADERS}
    assert "X-Forwarded-For" in names
    assert "X-Original-URL" in names


def test_header_fuzz_content_types_defined():
    from workers.fuzzing_worker.tools.header_fuzz_tool import CONTENT_TYPES
    assert "application/xml" in CONTENT_TYPES
    assert "text/yaml" in CONTENT_TYPES


@pytest.mark.anyio
async def test_header_fuzz_detects_status_change():
    from workers.fuzzing_worker.tools.header_fuzz_tool import HeaderFuzzTool
    tool = HeaderFuzzTool()
    assert tool.is_significant_deviation(403, 1000, 200, 1500) is True
    assert tool.is_significant_deviation(200, 1000, 200, 1050) is False
    assert tool.is_significant_deviation(200, 1000, 200, 1200) is True


@pytest.mark.anyio
async def test_header_fuzz_skips_on_cooldown():
    from workers.fuzzing_worker.tools.header_fuzz_tool import HeaderFuzzTool
    tool = HeaderFuzzTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True
