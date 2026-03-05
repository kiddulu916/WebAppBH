import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


# ---------------------------------------------------------------------------
# JsCrawler tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_js_crawler_executes_with_mocked_browser(tmp_path):
    """JsCrawler should crawl pages, capture JS responses, and save inline scripts."""
    from workers.webapp_worker.tools.js_crawler import JsCrawler

    crawler = JsCrawler()

    # ---- Mock BrowserManager ----
    browser_mgr = MagicMock()
    mock_page = MagicMock()
    mock_page.goto = AsyncMock()
    mock_page.on = MagicMock()  # page.on is synchronous (registers callback)
    mock_page.evaluate = AsyncMock(return_value=["var x = 1;"])
    mock_page.close = AsyncMock()
    browser_mgr.new_page = AsyncMock(return_value=mock_page)
    browser_mgr.release_page = AsyncMock()

    # ---- Mock scope_manager ----
    scope_mgr = MagicMock()

    with (
        patch.object(
            crawler, "_get_live_urls", new_callable=AsyncMock,
            return_value=[(1, "example.com")],
        ),
        patch.object(
            crawler, "check_cooldown", new_callable=AsyncMock,
            return_value=False,
        ),
        patch.object(
            crawler, "update_tool_state", new_callable=AsyncMock,
        ),
        patch.object(
            crawler, "_save_asset", new_callable=AsyncMock,
            return_value=10,
        ),
        patch("workers.webapp_worker.tools.js_crawler.JS_DIR", str(tmp_path)),
    ):
        result = await crawler.execute(
            target="example.com",
            scope_manager=scope_mgr,
            target_id=42,
            container_name="webapp-worker",
            headers={"User-Agent": "TestBot"},
            browser=browser_mgr,
        )

    # Verify cooldown not skipped
    assert result["skipped_cooldown"] is False

    # Verify browser interaction
    browser_mgr.new_page.assert_awaited()
    browser_mgr.release_page.assert_awaited()

    # Verify page.goto was called with https first
    mock_page.goto.assert_awaited()
    goto_url = mock_page.goto.call_args_list[0][0][0]
    assert goto_url.startswith("https://")

    # Verify page.on was called to register response handler
    mock_page.on.assert_called()

    # Verify inline scripts were extracted via evaluate
    mock_page.evaluate.assert_awaited()

    # Verify JS output directory was created
    js_dir = tmp_path / "42" / "js"
    assert js_dir.exists()

    # Verify inline script was saved
    inline_files = list(js_dir.glob("inline_*.js"))
    assert len(inline_files) == 1
    assert inline_files[0].read_text() == "var x = 1;"


@pytest.mark.anyio
async def test_js_crawler_skips_on_cooldown(tmp_path):
    """JsCrawler returns early with skipped_cooldown=True when within cooldown."""
    from workers.webapp_worker.tools.js_crawler import JsCrawler

    crawler = JsCrawler()
    scope_mgr = MagicMock()

    with patch.object(
        crawler, "check_cooldown", new_callable=AsyncMock,
        return_value=True,
    ):
        result = await crawler.execute(
            target="example.com",
            scope_manager=scope_mgr,
            target_id=42,
            container_name="webapp-worker",
        )

    assert result["skipped_cooldown"] is True


@pytest.mark.anyio
async def test_js_crawler_returns_early_without_browser(tmp_path):
    """JsCrawler returns early when no browser kwarg is provided."""
    from workers.webapp_worker.tools.js_crawler import JsCrawler

    crawler = JsCrawler()
    scope_mgr = MagicMock()

    with (
        patch.object(
            crawler, "check_cooldown", new_callable=AsyncMock,
            return_value=False,
        ),
        patch.object(
            crawler, "_get_live_urls", new_callable=AsyncMock,
            return_value=[(1, "example.com")],
        ),
    ):
        result = await crawler.execute(
            target="example.com",
            scope_manager=scope_mgr,
            target_id=42,
            container_name="webapp-worker",
            # No browser= kwarg
        )

    assert result["skipped_cooldown"] is False
    assert result["js_files_saved"] == 0


@pytest.mark.anyio
async def test_js_crawler_falls_back_to_http(tmp_path):
    """JsCrawler tries http when https page.goto raises an exception."""
    from workers.webapp_worker.tools.js_crawler import JsCrawler

    crawler = JsCrawler()

    browser_mgr = MagicMock()
    mock_page = MagicMock()

    # First call (https) raises, second call (http) succeeds
    mock_page.goto = AsyncMock(
        side_effect=[Exception("Connection refused"), None]
    )
    mock_page.on = MagicMock()
    mock_page.evaluate = AsyncMock(return_value=[])
    mock_page.close = AsyncMock()
    browser_mgr.new_page = AsyncMock(return_value=mock_page)
    browser_mgr.release_page = AsyncMock()

    scope_mgr = MagicMock()

    with (
        patch.object(
            crawler, "_get_live_urls", new_callable=AsyncMock,
            return_value=[(1, "example.com")],
        ),
        patch.object(
            crawler, "check_cooldown", new_callable=AsyncMock,
            return_value=False,
        ),
        patch.object(
            crawler, "update_tool_state", new_callable=AsyncMock,
        ),
        patch.object(
            crawler, "_save_asset", new_callable=AsyncMock,
            return_value=10,
        ),
        patch("workers.webapp_worker.tools.js_crawler.JS_DIR", str(tmp_path)),
    ):
        result = await crawler.execute(
            target="example.com",
            scope_manager=scope_mgr,
            target_id=42,
            container_name="webapp-worker",
            browser=browser_mgr,
        )

    # Both https and http were attempted
    assert mock_page.goto.await_count == 2
    goto_calls = [c[0][0] for c in mock_page.goto.call_args_list]
    assert goto_calls[0].startswith("https://")
    assert goto_calls[1].startswith("http://")

    # release_page still called (cleanup)
    browser_mgr.release_page.assert_awaited()


@pytest.mark.anyio
async def test_js_crawler_class_attributes():
    """Verify JsCrawler has correct class-level attributes."""
    from workers.webapp_worker.tools.js_crawler import JsCrawler
    from workers.webapp_worker.base_tool import ToolType
    from workers.webapp_worker.concurrency import WeightClass

    assert JsCrawler.name == "js_crawler"
    assert JsCrawler.tool_type == ToolType.BROWSER
    assert JsCrawler.weight_class == WeightClass.HEAVY


# ---------------------------------------------------------------------------
# LinkFinder tests
# ---------------------------------------------------------------------------


def test_linkfinder_parses_endpoints():
    """LinkFinder.parse_output splits lines and filters empty/bracket lines."""
    from workers.webapp_worker.tools.linkfinder import LinkFinder

    stdout = "/api/users\n/api/v1/login\n/health\n"
    results = LinkFinder.parse_output(stdout)
    assert results == ["/api/users", "/api/v1/login", "/health"]


# ---------------------------------------------------------------------------
# JsMiner tests
# ---------------------------------------------------------------------------


def test_jsminer_parses_json_output():
    """JsMiner.parse_output handles JSON array output."""
    from workers.webapp_worker.tools.jsminer import JsMiner

    stdout = '["/api/secret", "/admin/config"]\n'
    results = JsMiner.parse_output(stdout)
    assert results == ["/api/secret", "/admin/config"]


def test_jsminer_parses_line_output():
    """JsMiner.parse_output falls back to line-per-line for non-JSON output."""
    from workers.webapp_worker.tools.jsminer import JsMiner

    stdout = "/path1\n/path2\n"
    results = JsMiner.parse_output(stdout)
    assert results == ["/path1", "/path2"]


# ---------------------------------------------------------------------------
# Mantra tests
# ---------------------------------------------------------------------------


def test_mantra_parses_secrets():
    """Mantra.parse_output parses JSON-per-line secrets output."""
    from workers.webapp_worker.tools.mantra import Mantra

    stdout = '{"file":"main.js","type":"AWS Key","match":"AKIA1234"}\n'
    results = Mantra.parse_output(stdout)
    assert len(results) == 1
    assert results[0]["type"] == "AWS Key"


# ---------------------------------------------------------------------------
# SecretFinder tests
# ---------------------------------------------------------------------------


def test_secretfinder_parses_secrets():
    """SecretFinder.parse_output splits line-per-line findings."""
    from workers.webapp_worker.tools.secretfinder import SecretFinder

    stdout = "APIKey: sk_live_abc123\nBearer: eyJhbGci...\n"
    results = SecretFinder.parse_output(stdout)
    assert len(results) == 2


# ---------------------------------------------------------------------------
# PostMessage tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_postmessage_detects_insecure_listener():
    """PostMessage should flag listeners that lack origin validation."""
    from workers.webapp_worker.tools.postmessage import PostMessage

    tool = PostMessage()

    # ---- Mock BrowserManager ----
    browser_mgr = MagicMock()
    mock_page = MagicMock()
    mock_page.add_init_script = AsyncMock()
    mock_page.goto = AsyncMock()
    mock_page.evaluate = AsyncMock(
        return_value=[
            {
                "has_origin_check": False,
                "handler_preview": "fn(e){doStuff(e.data)}",
            }
        ]
    )
    browser_mgr.new_page = AsyncMock(return_value=mock_page)
    browser_mgr.release_page = AsyncMock()

    scope_mgr = MagicMock()

    save_vuln = AsyncMock(return_value=100)

    with (
        patch.object(
            tool, "_get_live_urls", new_callable=AsyncMock,
            return_value=[(1, "example.com")],
        ),
        patch.object(
            tool, "check_cooldown", new_callable=AsyncMock,
            return_value=False,
        ),
        patch.object(
            tool, "update_tool_state", new_callable=AsyncMock,
        ),
        patch.object(
            tool, "_save_vulnerability", save_vuln,
        ),
    ):
        result = await tool.execute(
            target="example.com",
            scope_manager=scope_mgr,
            target_id=42,
            container_name="webapp-worker",
            browser=browser_mgr,
        )

    # Verify vulnerability was saved for the insecure listener
    save_vuln.assert_awaited_once()
    call_kwargs = save_vuln.call_args[1]
    assert call_kwargs["severity"] == "high"
    assert "Insecure postMessage listener" in call_kwargs["title"]
    assert result["insecure_listeners"] == 1
    assert result["skipped_cooldown"] is False

    # Verify page cleanup
    browser_mgr.release_page.assert_awaited()


# ---------------------------------------------------------------------------
# DomSinkAnalyzer tests
# ---------------------------------------------------------------------------


def test_dom_sink_analyzer_detects_sinks():
    """_find_sinks should detect dangerous DOM sink patterns in JS code."""
    from workers.webapp_worker.tools.dom_sink_analyzer import _find_sinks

    # This JS code contains an innerHTML sink and a setTimeout sink
    js_code = (
        "element.innerHTML = input;\n"
        "setTimeout(data, 1000);"
    )
    sinks = _find_sinks(js_code)

    # Should detect at least one sink mentioning "innerHTML"
    assert len(sinks) >= 1
    assert any("innerHTML" in s for s in sinks)


def test_dom_sink_analyzer_detects_sources():
    """_find_sources should detect user-controllable DOM sources."""
    from workers.webapp_worker.tools.dom_sink_analyzer import _find_sources

    js_code = "var q = location.hash; var r = document.referrer;"
    sources = _find_sources(js_code)

    assert len(sources) >= 2
    assert any("location.hash" in s for s in sources)
    assert any("document.referrer" in s for s in sources)


@pytest.mark.anyio
async def test_dom_sink_analyzer_static_phase(tmp_path):
    """DomSinkAnalyzer Phase 1 should flag files with sinks + sources."""
    from workers.webapp_worker.tools.dom_sink_analyzer import DomSinkAnalyzer

    tool = DomSinkAnalyzer()
    scope_mgr = MagicMock()

    # Create a JS file with both sinks and sources
    js_dir = tmp_path / "42" / "js"
    js_dir.mkdir(parents=True)
    js_file = js_dir / "vuln.js"
    # Intentionally contains dangerous patterns for security testing
    js_file.write_text(
        "var input = location.hash;\n"
        "document.getElementById('x').innerHTML = input;\n"
    )

    save_vuln = AsyncMock(return_value=200)

    with (
        patch.object(
            tool, "check_cooldown", new_callable=AsyncMock,
            return_value=False,
        ),
        patch.object(
            tool, "update_tool_state", new_callable=AsyncMock,
        ),
        patch.object(
            tool, "_get_live_urls", new_callable=AsyncMock,
            return_value=[(1, "example.com")],
        ),
        patch.object(
            tool, "_save_vulnerability", save_vuln,
        ),
        patch(
            "workers.webapp_worker.tools.dom_sink_analyzer.JS_DIR",
            str(tmp_path),
        ),
    ):
        result = await tool.execute(
            target="example.com",
            scope_manager=scope_mgr,
            target_id=42,
            container_name="webapp-worker",
            # No browser — only static phase runs
        )

    assert result["files_scanned"] == 1
    assert result["source_sink_vulns"] == 1
    save_vuln.assert_awaited_once()
    call_kwargs = save_vuln.call_args[1]
    assert "Potential DOM XSS" in call_kwargs["title"]
    assert call_kwargs["severity"] == "high"


# ---------------------------------------------------------------------------
# StorageAuditor tests
# ---------------------------------------------------------------------------


def test_storage_auditor_is_sensitive():
    """_is_sensitive should match auth-related storage keys."""
    from workers.webapp_worker.tools.storage_auditor import StorageAuditor

    tool = StorageAuditor()
    assert tool._is_sensitive("auth_token") is True
    assert tool._is_sensitive("api_key") is True
    assert tool._is_sensitive("sessionId") is True
    assert tool._is_sensitive("jwt_refresh") is True
    assert tool._is_sensitive("theme_preference") is False
    assert tool._is_sensitive("language") is False


@pytest.mark.anyio
async def test_storage_auditor_flags_sensitive_storage():
    """StorageAuditor should flag sensitive keys found in browser storage."""
    from workers.webapp_worker.tools.storage_auditor import StorageAuditor

    tool = StorageAuditor()

    browser_mgr = MagicMock()
    mock_page = MagicMock()
    mock_page.goto = AsyncMock()
    mock_page.evaluate = AsyncMock(return_value=[
        {"store": "localStorage", "key": "auth_token", "value": "abc123"},
        {"store": "localStorage", "key": "theme", "value": "dark"},
    ])
    browser_mgr.new_page = AsyncMock(return_value=mock_page)
    browser_mgr.release_page = AsyncMock()

    scope_mgr = MagicMock()
    save_vuln = AsyncMock(return_value=100)

    with (
        patch.object(tool, "_get_live_urls", new_callable=AsyncMock,
                     return_value=[(1, "example.com")]),
        patch.object(tool, "check_cooldown", new_callable=AsyncMock,
                     return_value=False),
        patch.object(tool, "update_tool_state", new_callable=AsyncMock),
        patch.object(tool, "_save_vulnerability", save_vuln),
    ):
        result = await tool.execute(
            target="example.com",
            scope_manager=scope_mgr,
            target_id=42,
            container_name="webapp-worker",
            browser=browser_mgr,
        )

    assert result["urls_checked"] == 1
    assert result["sensitive_keys_found"] == 1
    save_vuln.assert_awaited_once()
    assert "auth_token" in save_vuln.call_args[1]["title"]
    browser_mgr.release_page.assert_awaited()


# ---------------------------------------------------------------------------
# SourcemapDetector tests
# ---------------------------------------------------------------------------


def test_sourcemap_detector_get_map_url():
    """_get_map_url should append .map to JS URL."""
    from workers.webapp_worker.tools.sourcemap_detector import SourcemapDetector

    assert SourcemapDetector._get_map_url("https://cdn.example.com/app.js") == "https://cdn.example.com/app.js.map"
    assert SourcemapDetector._get_map_url("https://cdn.example.com/bundle.min.js") == "https://cdn.example.com/bundle.min.js.map"


# ---------------------------------------------------------------------------
# WebSocketAnalyzer tests
# ---------------------------------------------------------------------------


def test_websocket_analyzer_attributes():
    """Verify WebSocketAnalyzer has correct class-level attributes."""
    from workers.webapp_worker.tools.websocket_analyzer import WebSocketAnalyzer
    from workers.webapp_worker.base_tool import ToolType
    from workers.webapp_worker.concurrency import WeightClass

    assert WebSocketAnalyzer.name == "websocket_analyzer"
    assert WebSocketAnalyzer.tool_type == ToolType.BROWSER
    assert WebSocketAnalyzer.weight_class == WeightClass.HEAVY


# ---------------------------------------------------------------------------
# HeaderAuditor tests
# ---------------------------------------------------------------------------


def test_header_auditor_detects_missing_headers():
    """_check_headers should report missing security headers."""
    from workers.webapp_worker.tools.header_auditor import HeaderAuditor

    # Response with only Content-Type — missing all security headers
    resp_headers = {"Content-Type": "text/html"}
    missing = HeaderAuditor._check_headers(resp_headers)
    assert len(missing) >= 2
    assert any("HSTS" in m for m in missing)
    assert any("CSP" in m for m in missing)


def test_header_auditor_passes_when_present():
    """_check_headers should return empty list when all headers present."""
    from workers.webapp_worker.tools.header_auditor import HeaderAuditor

    resp_headers = {
        "Strict-Transport-Security": "max-age=63072000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin",
        "Permissions-Policy": "camera=()",
    }
    missing = HeaderAuditor._check_headers(resp_headers)
    assert missing == []


# ---------------------------------------------------------------------------
# CookieAuditor tests
# ---------------------------------------------------------------------------


def test_cookie_auditor_detects_insecure_cookies():
    """_check_cookie should flag missing Secure, HttpOnly, SameSite."""
    from workers.webapp_worker.tools.cookie_auditor import CookieAuditor

    issues = CookieAuditor._check_cookie("session=abc; Path=/")
    assert len(issues) == 3
    assert any("Secure" in i for i in issues)
    assert any("HttpOnly" in i for i in issues)
    assert any("SameSite" in i for i in issues)


def test_cookie_auditor_passes_secure_cookie():
    """_check_cookie should return empty list for fully secured cookie."""
    from workers.webapp_worker.tools.cookie_auditor import CookieAuditor

    issues = CookieAuditor._check_cookie(
        "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict"
    )
    assert issues == []


# ---------------------------------------------------------------------------
# CorsTester tests
# ---------------------------------------------------------------------------


def test_cors_tester_detects_reflection():
    """_is_cors_misconfigured should detect reflected origin."""
    from workers.webapp_worker.tools.cors_tester import CorsTester

    headers = {
        "access-control-allow-origin": "https://attacker.com",
        "access-control-allow-credentials": "true",
    }
    assert CorsTester._is_cors_misconfigured(headers, "https://attacker.com") is True


def test_cors_tester_detects_null_origin():
    """_is_cors_misconfigured should detect null origin reflection."""
    from workers.webapp_worker.tools.cors_tester import CorsTester

    headers = {"access-control-allow-origin": "null"}
    assert CorsTester._is_cors_misconfigured(headers, "null") is True


def test_cors_tester_passes_safe_config():
    """_is_cors_misconfigured should return False for safe CORS."""
    from workers.webapp_worker.tools.cors_tester import CorsTester

    headers = {"access-control-allow-origin": "https://trusted.com"}
    assert CorsTester._is_cors_misconfigured(headers, "https://attacker.com") is False


# ---------------------------------------------------------------------------
# FormAnalyzer tests
# ---------------------------------------------------------------------------


def test_form_analyzer_detects_missing_csrf():
    """_analyze_forms should flag POST forms without CSRF tokens."""
    from workers.webapp_worker.tools.form_analyzer import FormAnalyzer

    html = '<form method="post" action="/login"><input type="text" name="user"><input type="submit"></form>'
    issues = FormAnalyzer._analyze_forms(html)
    assert len(issues) >= 1
    assert any("CSRF" in i for i in issues)


def test_form_analyzer_passes_with_csrf():
    """_analyze_forms should pass POST forms with CSRF tokens."""
    from workers.webapp_worker.tools.form_analyzer import FormAnalyzer

    html = '<form method="post" action="/login"><input type="hidden" name="csrf" value="abc123"><input type="submit"></form>'
    issues = FormAnalyzer._analyze_forms(html)
    csrf_issues = [i for i in issues if "CSRF" in i]
    assert len(csrf_issues) == 0


# ---------------------------------------------------------------------------
# SensitivePaths tests
# ---------------------------------------------------------------------------


def test_sensitive_paths_has_wordlist():
    """SENSITIVE_WORDLIST should contain key paths."""
    from workers.webapp_worker.tools.sensitive_paths import SENSITIVE_WORDLIST

    assert len(SENSITIVE_WORDLIST) >= 10
    assert "/.git/HEAD" in SENSITIVE_WORDLIST
    assert "/.env" in SENSITIVE_WORDLIST


# ---------------------------------------------------------------------------
# RobotsSitemap tests
# ---------------------------------------------------------------------------


def test_robots_sitemap_parses_robots():
    """_parse_robots should extract disallow/allow paths."""
    from workers.webapp_worker.tools.robots_sitemap import RobotsSitemap

    robots_txt = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /private/secret\n"
        "Allow: /public/\n"
    )
    paths = RobotsSitemap._parse_robots(robots_txt)
    assert "/admin/" in paths
    assert "/private/secret" in paths
    assert "/public/" in paths


def test_robots_sitemap_parses_sitemap():
    """_parse_sitemap should extract loc URLs from XML."""
    from workers.webapp_worker.tools.robots_sitemap import RobotsSitemap

    xml = (
        '<?xml version="1.0"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://example.com/page1</loc></url>"
        "<url><loc>https://example.com/page2</loc></url>"
        "</urlset>"
    )
    urls = RobotsSitemap._parse_sitemap(xml)
    assert len(urls) == 2
    assert "https://example.com/page1" in urls


# ---------------------------------------------------------------------------
# GraphqlProber tests
# ---------------------------------------------------------------------------


def test_graphql_prober_has_common_paths():
    """GRAPHQL_PATHS should contain standard GraphQL paths."""
    from workers.webapp_worker.tools.graphql_prober import GRAPHQL_PATHS

    assert "/graphql" in GRAPHQL_PATHS
    assert "/api/graphql" in GRAPHQL_PATHS


# ---------------------------------------------------------------------------
# OpenApiDetector tests
# ---------------------------------------------------------------------------


def test_openapi_detector_has_common_paths():
    """OPENAPI_PATHS should contain standard OpenAPI/Swagger paths."""
    from workers.webapp_worker.tools.openapi_detector import OPENAPI_PATHS

    assert "/swagger.json" in OPENAPI_PATHS
    assert "/api-docs" in OPENAPI_PATHS


# ---------------------------------------------------------------------------
# OpenRedirect tests
# ---------------------------------------------------------------------------


def test_open_redirect_identifies_redirect_params():
    """REDIRECT_PARAMS should contain common redirect parameter names."""
    from workers.webapp_worker.tools.open_redirect import REDIRECT_PARAMS

    assert "redirect" in REDIRECT_PARAMS
    assert "url" in REDIRECT_PARAMS
    assert "next" in REDIRECT_PARAMS
    assert "return" in REDIRECT_PARAMS


# ---------------------------------------------------------------------------
# NewmanProber tests
# ---------------------------------------------------------------------------


def test_newman_prober_generates_collection():
    """_build_collection should produce a valid Postman collection."""
    from workers.webapp_worker.tools.newman_prober import NewmanProber

    endpoints = ["https://example.com/api/users", "https://example.com/api/items"]
    collection = NewmanProber._build_collection(endpoints, "example.com")

    assert "info" in collection
    assert "item" in collection
    assert collection["info"]["name"] == "WebAppBH Auto-Collection: example.com"

    # 2 endpoints * 4 methods = 8 items
    assert len(collection["item"]) == 8

    for item in collection["item"]:
        assert "request" in item
        assert "method" in item["request"]
        assert "url" in item["request"]
        assert item["request"]["method"] in ("GET", "POST", "PUT", "DELETE")
