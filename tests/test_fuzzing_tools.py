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
    from workers.fuzzing_worker.tools.feroxbuster_tool import FeroxbusterTool
    tool = FeroxbusterTool()
    scope_mgr = MagicMock()
    target = MagicMock(target_profile={"rate_limit": 50})

    with (
        patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=False),
        patch.object(tool, "run_subprocess", new_callable=AsyncMock, return_value=SAMPLE_FEROX_LINES),
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
