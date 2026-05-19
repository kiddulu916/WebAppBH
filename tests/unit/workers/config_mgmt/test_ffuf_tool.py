"""Unit tests for extended FfufTool (WSTG-CONF-04)."""

from unittest.mock import AsyncMock, MagicMock, patch
import os
import json
import tempfile

import pytest

from workers.config_mgmt.tools.ffuf_tool import (
    FfufTool,
    _build_supplemental_wordlist,
    _classify_ffuf_result,
    _extract_dir_paths,
    _parse_ffuf_file,
    _build_ffuf_cmd,
)


# ── _extract_dir_paths ────────────────────────────────────────────────────────

def test_extract_dir_paths_returns_parent_dirs():
    result = _extract_dir_paths(["https://example.com/app/admin/login.php"])
    assert "/app/admin" in result


def test_extract_dir_paths_deduplicates():
    result = _extract_dir_paths([
        "https://example.com/app/admin/a.php",
        "https://example.com/app/admin/b.php",
    ])
    assert result.count("/app/admin") == 1


def test_extract_dir_paths_skips_root_files():
    result = _extract_dir_paths(["https://example.com/index.php"])
    assert result == []


# ── _build_supplemental_wordlist ──────────────────────────────────────────────

def test_build_supplemental_wordlist_returns_entries_for_extensions():
    result = _build_supplemental_wordlist([".php"])
    assert any(line.endswith(".bak") for line in result)
    assert any(".php" in line for line in result)


def test_build_supplemental_wordlist_caps_at_200():
    # Many extensions → hard cap at 200 entries
    extensions = [f".ext{i}" for i in range(50)]
    result = _build_supplemental_wordlist(extensions)
    assert len(result) <= 200


def test_build_supplemental_wordlist_empty_for_no_extensions():
    result = _build_supplemental_wordlist([])
    assert result == []


# ── _classify_ffuf_result ─────────────────────────────────────────────────────

def test_classify_ffuf_result_db_ext_is_critical():
    result = _classify_ffuf_result("/dump.sql", 200, "https://example.com/dump.sql")
    assert result["vulnerability"]["severity"] == "critical"
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-04"


def test_classify_ffuf_result_backup_ext_is_high():
    result = _classify_ffuf_result("/config.php.bak", 200, "https://example.com/config.php.bak")
    assert result["vulnerability"]["severity"] == "high"


def test_classify_ffuf_result_tilde_is_high():
    result = _classify_ffuf_result("/index.php~", 200, "https://example.com/index.php~")
    assert result["vulnerability"]["severity"] == "high"


def test_classify_ffuf_result_archive_is_high():
    result = _classify_ffuf_result("/backup.zip", 200, "https://example.com/backup.zip")
    assert result["vulnerability"]["severity"] == "high"


def test_classify_ffuf_result_403_is_observation():
    result = _classify_ffuf_result("/admin", 403, "https://example.com/admin")
    assert "observation" in result
    assert result["observation"]["type"] == "ffuf_access_denied"


def test_classify_ffuf_result_401_is_observation():
    result = _classify_ffuf_result("/admin", 401, "https://example.com/admin")
    assert "observation" in result
    assert result["observation"]["details"]["status"] == 401


def test_classify_ffuf_result_generic_path_is_low():
    result = _classify_ffuf_result("/about", 200, "https://example.com/about")
    assert result["vulnerability"]["severity"] == "low"


# ── _parse_ffuf_file ──────────────────────────────────────────────────────────

def test_parse_ffuf_file_returns_results(tmp_path):
    data = {
        "results": [
            {"input": {"FUZZ": "config.php.bak"}, "status": 200, "url": "https://example.com/config.php.bak", "length": 512},
        ]
    }
    f = tmp_path / "ffuf_out.json"
    f.write_text(json.dumps(data))
    results = _parse_ffuf_file(str(f))
    assert len(results) == 1
    assert results[0]["path"] == "config.php.bak"
    assert results[0]["status"] == 200


def test_parse_ffuf_file_returns_empty_for_missing_file():
    results = _parse_ffuf_file("/tmp/nonexistent_ffuf_output.json")
    assert results == []


def test_parse_ffuf_file_deletes_file_after_reading(tmp_path):
    data = {"results": []}
    f = tmp_path / "ffuf_out.json"
    f.write_text(json.dumps(data))
    _parse_ffuf_file(str(f))
    assert not f.exists()


# ── _build_ffuf_cmd ───────────────────────────────────────────────────────────

def test_build_ffuf_cmd_basic_structure():
    cmd = _build_ffuf_cmd(
        url="https://example.com/FUZZ",
        wordlist="/wordlists/common.txt",
        output_file="/tmp/out.json",
        rate_limit=50,
        headers=None,
    )
    assert "ffuf" in cmd
    assert "https://example.com/FUZZ" in cmd
    assert "/wordlists/common.txt" in cmd
    assert "/tmp/out.json" in cmd
    assert "json" in cmd


def test_build_ffuf_cmd_includes_supplemental_wordlist():
    cmd = _build_ffuf_cmd(
        url="https://example.com/FUZZ",
        wordlist="/wordlists/common.txt",
        output_file="/tmp/out.json",
        rate_limit=50,
        headers=None,
        supplemental_wl="/tmp/supp.txt",
    )
    assert "/tmp/supp.txt" in cmd
    assert cmd.count("-w") >= 2


def test_build_ffuf_cmd_includes_headers():
    cmd = _build_ffuf_cmd(
        url="https://example.com/FUZZ",
        wordlist="/wordlists/common.txt",
        output_file="/tmp/out.json",
        rate_limit=50,
        headers={"X-API-KEY": "abc123"},
    )
    assert "X-API-KEY: abc123" in cmd


# ── execute() smoke tests ─────────────────────────────────────────────────────

async def test_ffuf_execute_skips_on_cooldown(monkeypatch):
    tool = FfufTool()
    monkeypatch.setattr(tool, "check_cooldown", AsyncMock(return_value=True))

    stats = await tool.execute(
        target=MagicMock(target_value="https://example.com"),
        scope_manager=MagicMock(),
        target_id=1,
        container_name="config_mgmt",
    )
    assert stats == {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}


async def test_ffuf_execute_runs_and_returns_stats(monkeypatch):
    tool = FfufTool()

    monkeypatch.setattr(tool, "check_cooldown", AsyncMock(return_value=False))

    mock_sem = MagicMock()
    mock_sem.acquire = AsyncMock()
    mock_sem.release = MagicMock()
    monkeypatch.setattr(
        "workers.config_mgmt.tools.ffuf_tool.get_semaphore",
        lambda _: mock_sem,
    )
    monkeypatch.setattr(
        "workers.config_mgmt.tools.ffuf_tool.push_task",
        AsyncMock(),
    )

    # DB: no discovered dirs/extensions
    session = MagicMock()
    empty_scalars = MagicMock()
    empty_scalars.all.return_value = []
    empty_result = MagicMock()
    empty_result.scalars.return_value = empty_scalars
    empty_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=empty_result)
    session.commit = AsyncMock()

    def fake_get_session():
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=session)
        ctx.__aexit__ = AsyncMock(return_value=False)
        return ctx

    monkeypatch.setattr("workers.config_mgmt.tools.ffuf_tool.get_session", fake_get_session)

    # run_subprocess: writes a ffuf JSON output file with one finding
    async def fake_run_subprocess(cmd, timeout=600):
        # find -o argument in cmd and write a fake result
        try:
            idx = cmd.index("-o")
            out_file = cmd[idx + 1]
            with open(out_file, "w") as f:
                json.dump({
                    "results": [
                        {
                            "input": {"FUZZ": "backup.zip"},
                            "status": 200,
                            "url": "https://example.com/backup.zip",
                            "length": 1024,
                        }
                    ]
                }, f)
        except (ValueError, IndexError):
            pass
        return ""

    monkeypatch.setattr(tool, "run_subprocess", fake_run_subprocess)
    monkeypatch.setattr(tool, "_process_result", AsyncMock(return_value=True))

    stats = await tool.execute(
        target=MagicMock(target_value="https://example.com"),
        scope_manager=MagicMock(),
        target_id=1,
        container_name="config_mgmt",
    )

    assert stats["found"] >= 1
    assert stats["skipped_cooldown"] is False
