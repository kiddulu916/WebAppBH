"""Unit tests for WSTG-CONF-04 BackupFileFinder pure functions."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from workers.config_mgmt.tools.backup_file_finder import (
    BackupFileFinder,
    _analyze_mutation,
    _analyze_static_probe,
    _extract_directories,
    _extract_domain,
    _extract_path_pairs,
    _generate_mutations,
    _parse_robots_txt,
)


# ── _extract_path_pairs ───────────────────────────────────────────────────────

def test_extract_path_pairs_returns_stem_ext_tuples():
    result = _extract_path_pairs(["https://example.com/login.php"])
    assert ("/login", ".php") in result


def test_extract_path_pairs_deduplicates():
    result = _extract_path_pairs([
        "https://example.com/login.php",
        "https://example.com/login.php",
    ])
    assert result.count(("/login", ".php")) == 1


def test_extract_path_pairs_skips_bare_paths_without_extension():
    result = _extract_path_pairs(["https://example.com/api/v1"])
    assert result == []


def test_extract_path_pairs_skips_root():
    result = _extract_path_pairs(["https://example.com/"])
    assert result == []


# ── _generate_mutations ───────────────────────────────────────────────────────

def test_generate_mutations_includes_ext_plus_bak():
    result = _generate_mutations("/login", ".php")
    assert "/login.php.bak" in result


def test_generate_mutations_includes_tilde():
    result = _generate_mutations("/login", ".php")
    assert "/login.php~" in result


def test_generate_mutations_includes_bare_stem_bak():
    result = _generate_mutations("/login", ".php")
    assert "/login.bak" in result


def test_generate_mutations_includes_bare_stem_old():
    result = _generate_mutations("/login", ".php")
    assert "/login.old" in result


def test_generate_mutations_count():
    # 11 suffixes appended to stem+ext + 2 bare-stem variants = 13
    assert len(_generate_mutations("/config", ".yml")) == 13


# ── _extract_directories ──────────────────────────────────────────────────────

def test_extract_directories_returns_parent_dir():
    result = _extract_directories(["https://example.com/app/admin/login.php"])
    assert "/app/admin" in result


def test_extract_directories_deduplicates():
    result = _extract_directories([
        "https://example.com/app/admin/login.php",
        "https://example.com/app/admin/dashboard.php",
    ])
    assert result.count("/app/admin") == 1


def test_extract_directories_skips_root_files():
    result = _extract_directories(["https://example.com/index.php"])
    assert result == []


# ── _extract_domain ───────────────────────────────────────────────────────────

def test_extract_domain_from_https_url():
    assert _extract_domain("https://example.com/path") == "example.com"


def test_extract_domain_from_bare_hostname():
    assert _extract_domain("example.com") == "example.com"


def test_extract_domain_from_hostname_with_port():
    assert _extract_domain("example.com:8080") == "example.com"


def test_extract_domain_from_http_url():
    assert _extract_domain("http://sub.example.com") == "sub.example.com"


# ── _parse_robots_txt ─────────────────────────────────────────────────────────

def test_parse_robots_txt_extracts_disallow_paths():
    body = "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
    result = _parse_robots_txt(body)
    assert "/admin" in result
    assert "/backup" in result


def test_parse_robots_txt_skips_root_disallow():
    body = "Disallow: /\n"
    result = _parse_robots_txt(body)
    assert result == []


def test_parse_robots_txt_handles_empty_disallow():
    body = "Disallow: \n"
    result = _parse_robots_txt(body)
    assert result == []


def test_parse_robots_txt_case_insensitive():
    body = "DISALLOW: /secret\n"
    result = _parse_robots_txt(body)
    assert "/secret" in result


# ── _analyze_static_probe ─────────────────────────────────────────────────────

def test_analyze_static_probe_env_200_is_high():
    result = _analyze_static_probe(
        "https://example.com/.env", "/.env", 200, "", "text/plain"
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-04"


def test_analyze_static_probe_db_dump_200_is_critical():
    result = _analyze_static_probe(
        "https://example.com/dump.sql", "/dump.sql", 200, "-- SQL dump", "text/plain"
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"


def test_analyze_static_probe_credentials_upgrade_to_critical():
    result = _analyze_static_probe(
        "https://example.com/.env", "/.env", 200, "password=secret123", "text/plain"
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"


def test_analyze_static_probe_source_control_dir_403_is_observation():
    result = _analyze_static_probe(
        "https://example.com/.git/", "/.git/", 403, "", "text/html"
    )
    assert result is not None
    assert "observation" in result
    assert result["observation"]["type"] == "backup_access_denied"


def test_analyze_static_probe_source_control_dir_200_is_vulnerability():
    result = _analyze_static_probe(
        "https://example.com/.git/", "/.git/", 200, "ref: refs/heads/main", "text/plain"
    )
    assert result is not None
    assert "vulnerability" in result


def test_analyze_static_probe_404_returns_none():
    result = _analyze_static_probe(
        "https://example.com/.env", "/.env", 404, "", "text/html"
    )
    assert result is None


def test_analyze_static_probe_unknown_path_returns_none():
    result = _analyze_static_probe(
        "https://example.com/unknown.xyz", "/unknown.xyz", 200, "", "text/html"
    )
    assert result is None


def test_analyze_static_probe_source_syntax_upgrades_to_high():
    result = _analyze_static_probe(
        "https://example.com/config.bak", "/config.bak", 200,
        "<?php include_once('db.php'); ?>", "text/plain"
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"


# ── _analyze_mutation ─────────────────────────────────────────────────────────

def test_analyze_mutation_200_is_high():
    result = _analyze_mutation(
        "https://example.com/login.php.bak", "/login", ".php", 200, "", "text/plain"
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "high"
    assert result["vulnerability"]["section_id"] == "WSTG-CONF-04"


def test_analyze_mutation_credentials_upgrade_to_critical():
    result = _analyze_mutation(
        "https://example.com/config.php.bak", "/config", ".php",
        200, "password=secret", "text/plain"
    )
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"


def test_analyze_mutation_404_returns_none():
    result = _analyze_mutation(
        "https://example.com/login.php.bak", "/login", ".php", 404, "", "text/html"
    )
    assert result is None


# ── execute() smoke tests ─────────────────────────────────────────────────────

async def test_execute_skips_on_cooldown(monkeypatch):
    tool = BackupFileFinder()
    monkeypatch.setattr(tool, "check_cooldown", AsyncMock(return_value=True))

    stats = await tool.execute(
        target=MagicMock(target_value="https://example.com"),
        scope_manager=MagicMock(),
        target_id=1,
        container_name="config_mgmt",
    )
    assert stats == {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}


async def test_execute_returns_zero_when_out_of_scope(monkeypatch):
    tool = BackupFileFinder()
    monkeypatch.setattr(tool, "check_cooldown", AsyncMock(return_value=False))

    mock_sem = MagicMock()
    mock_sem.acquire = AsyncMock()
    mock_sem.release = MagicMock()
    monkeypatch.setattr(
        "workers.config_mgmt.tools.backup_file_finder.get_semaphore",
        lambda _: mock_sem,
    )
    monkeypatch.setattr(
        "workers.config_mgmt.tools.backup_file_finder.push_task",
        AsyncMock(),
    )

    scope_result = MagicMock()
    scope_result.in_scope = False
    scope_manager = MagicMock()
    scope_manager.is_in_scope.return_value = scope_result

    stats = await tool.execute(
        target=MagicMock(target_value="https://example.com"),
        scope_manager=scope_manager,
        target_id=1,
        container_name="config_mgmt",
    )
    assert stats == {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}


async def test_execute_returns_stats_on_finding(monkeypatch):
    tool = BackupFileFinder()

    monkeypatch.setattr(tool, "check_cooldown", AsyncMock(return_value=False))

    mock_sem = MagicMock()
    mock_sem.acquire = AsyncMock()
    mock_sem.release = MagicMock()
    monkeypatch.setattr(
        "workers.config_mgmt.tools.backup_file_finder.get_semaphore",
        lambda _: mock_sem,
    )
    monkeypatch.setattr(
        "workers.config_mgmt.tools.backup_file_finder.push_task",
        AsyncMock(),
    )

    # DB session: returns empty asset list and no job state
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

    monkeypatch.setattr(
        "workers.config_mgmt.tools.backup_file_finder.get_session",
        fake_get_session,
    )

    # httpx.AsyncClient: /.env returns 200 with a password; all else 404
    resp_env = MagicMock()
    resp_env.status_code = 200
    resp_env.text = "password=hunter2"
    resp_env.headers = {"content-type": "text/plain"}

    resp_404 = MagicMock()
    resp_404.status_code = 404
    resp_404.text = ""
    resp_404.headers = {"content-type": "text/html"}

    async def fake_get(url):
        return resp_env if url.endswith("/.env") else resp_404

    async def fake_head(url):
        return resp_404

    mock_client = MagicMock()
    mock_client.get = fake_get
    mock_client.head = fake_head
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    monkeypatch.setattr(
        "workers.config_mgmt.tools.backup_file_finder.httpx.AsyncClient",
        lambda **kwargs: mock_client,
    )

    monkeypatch.setattr(tool, "_process_result", AsyncMock(return_value=True))

    scope_result = MagicMock()
    scope_result.in_scope = True
    scope_manager = MagicMock()
    scope_manager.is_in_scope.return_value = scope_result

    stats = await tool.execute(
        target=MagicMock(target_value="https://example.com"),
        scope_manager=scope_manager,
        target_id=1,
        container_name="config_mgmt",
    )

    assert stats["found"] >= 1
    assert stats["new"] >= 1
    assert stats["skipped_cooldown"] is False
