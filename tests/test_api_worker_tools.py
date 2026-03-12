"""Tests for api_worker Stage 1-4 tools."""

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


# ===================================================================
# FfufApiTool tests
# ===================================================================

SAMPLE_FFUF_API_OUTPUT = json.dumps({
    "results": [
        {"url": "https://acme.com/api/v1/users", "status": 200, "length": 500},
        {"url": "https://acme.com/api/v1/admin", "status": 401, "length": 50},
        {"url": "https://acme.com/api/v1/health", "status": 200, "length": 20},
    ]
})


def test_ffuf_api_parse_output():
    from workers.api_worker.tools.ffuf_api_tool import FfufApiTool

    tool = FfufApiTool()
    results = tool.parse_output(SAMPLE_FFUF_API_OUTPUT)
    assert len(results) == 3
    assert results[0]["url"] == "https://acme.com/api/v1/users"


def test_ffuf_api_parse_output_bad_json():
    from workers.api_worker.tools.ffuf_api_tool import FfufApiTool

    tool = FfufApiTool()
    results = tool.parse_output("not-json")
    assert results == []


def test_ffuf_api_build_command():
    from workers.api_worker.tools.ffuf_api_tool import FfufApiTool

    tool = FfufApiTool()
    cmd = tool.build_command(
        url="https://acme.com/api/FUZZ",
        wordlist="/app/wordlists/api-endpoints.txt",
        rate_limit=50,
        method="GET",
        headers={"Authorization": "Bearer tok"},
        output_file="/tmp/ffuf.json",
    )
    assert "ffuf" in cmd
    assert "-X" in cmd
    assert "GET" in cmd
    assert "-H" in cmd
    # Should have Authorization header
    assert any("Authorization" in c for c in cmd)


def test_ffuf_api_build_command_post_adds_content_type():
    from workers.api_worker.tools.ffuf_api_tool import FfufApiTool

    tool = FfufApiTool()
    cmd = tool.build_command(
        url="https://acme.com/api/FUZZ",
        wordlist="/app/wordlists/api-endpoints.txt",
        rate_limit=50,
        method="POST",
        output_file="/tmp/ffuf.json",
    )
    assert "POST" in cmd
    assert "Content-Type: application/json" in cmd


@pytest.mark.anyio
async def test_ffuf_api_skips_on_cooldown():
    from workers.api_worker.tools.ffuf_api_tool import FfufApiTool

    tool = FfufApiTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
            headers={},
        )
    assert result.get("skipped_cooldown") is True


# ===================================================================
# OpenapiParserTool tests
# ===================================================================

SAMPLE_OPENAPI_SPEC = json.dumps({
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0"},
    "paths": {
        "/api/v1/users": {
            "get": {
                "parameters": [
                    {"name": "page", "in": "query"},
                    {"name": "limit", "in": "query"},
                ]
            },
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "properties": {
                                    "name": {"type": "string"},
                                    "email": {"type": "string"},
                                }
                            }
                        }
                    }
                }
            },
        },
        "/api/v1/users/{id}": {
            "get": {},
            "delete": {},
        },
    },
})


def test_openapi_parser_extracts_endpoints():
    from workers.api_worker.tools.openapi_parser import OpenapiParserTool

    tool = OpenapiParserTool()
    endpoints = tool.parse_spec(json.loads(SAMPLE_OPENAPI_SPEC))
    assert len(endpoints) == 4
    methods = {(e["method"], e["path"]) for e in endpoints}
    assert ("GET", "/api/v1/users") in methods
    assert ("POST", "/api/v1/users") in methods
    assert ("GET", "/api/v1/users/{id}") in methods
    assert ("DELETE", "/api/v1/users/{id}") in methods


def test_openapi_parser_extracts_query_params():
    from workers.api_worker.tools.openapi_parser import OpenapiParserTool

    tool = OpenapiParserTool()
    endpoints = tool.parse_spec(json.loads(SAMPLE_OPENAPI_SPEC))
    get_users = [
        e for e in endpoints
        if e["method"] == "GET" and e["path"] == "/api/v1/users"
    ][0]
    assert "query" in get_users["params"]
    assert "page" in get_users["params"]["query"]
    assert "limit" in get_users["params"]["query"]


def test_openapi_parser_extracts_body_params():
    from workers.api_worker.tools.openapi_parser import OpenapiParserTool

    tool = OpenapiParserTool()
    endpoints = tool.parse_spec(json.loads(SAMPLE_OPENAPI_SPEC))
    post_users = [
        e for e in endpoints
        if e["method"] == "POST" and e["path"] == "/api/v1/users"
    ][0]
    assert post_users["content_type"] == "application/json"
    assert "body" in post_users["params"]
    assert "name" in post_users["params"]["body"]
    assert "email" in post_users["params"]["body"]


def test_openapi_parser_empty_spec():
    from workers.api_worker.tools.openapi_parser import OpenapiParserTool

    tool = OpenapiParserTool()
    endpoints = tool.parse_spec({"openapi": "3.0.0", "paths": {}})
    assert endpoints == []


@pytest.mark.anyio
async def test_openapi_parser_skips_on_cooldown():
    from workers.api_worker.tools.openapi_parser import OpenapiParserTool

    tool = OpenapiParserTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
            headers={},
        )
    assert result.get("skipped_cooldown") is True


# ===================================================================
# GraphqlIntrospectTool tests
# ===================================================================

SAMPLE_INTROSPECTION_RESPONSE = json.dumps({
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "fields": [
                        {"name": "users", "args": [{"name": "limit"}]},
                        {"name": "user", "args": [{"name": "id"}]},
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "fields": [
                        {"name": "createUser", "args": [{"name": "input"}]},
                        {"name": "deleteUser", "args": [{"name": "id"}]},
                    ],
                },
                {
                    "kind": "SCALAR",
                    "name": "String",
                    "fields": None,
                },
            ],
        }
    }
})


def test_graphql_introspect_parses_schema():
    from workers.api_worker.tools.graphql_introspect import GraphqlIntrospectTool

    tool = GraphqlIntrospectTool()
    data = json.loads(SAMPLE_INTROSPECTION_RESPONSE)
    endpoints = tool.parse_introspection(data)
    assert len(endpoints) == 4
    names = {e["path"] for e in endpoints}
    assert "query:users" in names
    assert "query:user" in names
    assert "mutation:createUser" in names
    assert "mutation:deleteUser" in names


def test_graphql_introspect_methods():
    from workers.api_worker.tools.graphql_introspect import GraphqlIntrospectTool

    tool = GraphqlIntrospectTool()
    data = json.loads(SAMPLE_INTROSPECTION_RESPONSE)
    endpoints = tool.parse_introspection(data)
    query_eps = [e for e in endpoints if e["method"] == "QUERY"]
    mutation_eps = [e for e in endpoints if e["method"] == "MUTATION"]
    assert len(query_eps) == 2
    assert len(mutation_eps) == 2


def test_graphql_introspect_args():
    from workers.api_worker.tools.graphql_introspect import GraphqlIntrospectTool

    tool = GraphqlIntrospectTool()
    data = json.loads(SAMPLE_INTROSPECTION_RESPONSE)
    endpoints = tool.parse_introspection(data)
    users_ep = [e for e in endpoints if e["path"] == "query:users"][0]
    assert users_ep["params"] == {"args": ["limit"]}


def test_graphql_introspect_empty_schema():
    from workers.api_worker.tools.graphql_introspect import GraphqlIntrospectTool

    tool = GraphqlIntrospectTool()
    endpoints = tool.parse_introspection({"data": {"__schema": {"types": []}}})
    assert endpoints == []


@pytest.mark.anyio
async def test_graphql_introspect_skips_on_cooldown():
    from workers.api_worker.tools.graphql_introspect import GraphqlIntrospectTool

    tool = GraphqlIntrospectTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
            headers={},
        )
    assert result.get("skipped_cooldown") is True


@pytest.mark.anyio
async def test_graphql_introspect_inql_fallback():
    """InQL fallback is called when introspection returns non-200."""
    from workers.api_worker.tools.graphql_introspect import GraphqlIntrospectTool

    tool = GraphqlIntrospectTool()
    with (
        patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=False),
        patch.object(tool, "_get_live_urls", new_callable=AsyncMock, return_value=[(1, "https://acme.com")]),
        patch.object(tool, "_run_inql_fallback", new_callable=AsyncMock) as mock_inql,
        patch.object(tool, "update_tool_state", new_callable=AsyncMock),
        patch("workers.api_worker.tools.graphql_introspect.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_resp = MagicMock()
        mock_resp.status_code = 403  # introspection disabled
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.aclose = AsyncMock()
        mock_client_cls.return_value = mock_client

        await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
            headers={},
        )

    # InQL fallback should be called for each GRAPHQL_PATHS entry
    assert mock_inql.call_count > 0


# ===================================================================
# TrufflehogTool tests
# ===================================================================

SAMPLE_TRUFFLEHOG_OUTPUT = "\n".join([
    json.dumps({
        "SourceMetadata": {
            "Data": {"Filesystem": {"file": "/tmp/swagger.json"}}
        },
        "DetectorName": "AWS",
        "Raw": "AKIAIOSFODNN7EXAMPLE",
        "Verified": True,
    }),
    json.dumps({
        "SourceMetadata": {
            "Data": {"Filesystem": {"file": "/tmp/swagger.json"}}
        },
        "DetectorName": "Generic",
        "Raw": "sk_live_abc123",
        "Verified": False,
    }),
])


def test_trufflehog_parse_output():
    from workers.api_worker.tools.trufflehog_tool import TrufflehogTool

    tool = TrufflehogTool()
    findings = tool.parse_output(SAMPLE_TRUFFLEHOG_OUTPUT)
    assert len(findings) == 2
    assert findings[0]["detector"] == "AWS"
    assert findings[0]["verified"] is True
    assert findings[0]["file"] == "/tmp/swagger.json"
    assert findings[1]["detector"] == "Generic"
    assert findings[1]["verified"] is False


def test_trufflehog_parse_output_bad_lines():
    from workers.api_worker.tools.trufflehog_tool import TrufflehogTool

    tool = TrufflehogTool()
    findings = tool.parse_output("not-json\n\n")
    assert findings == []


def test_trufflehog_parse_output_empty():
    from workers.api_worker.tools.trufflehog_tool import TrufflehogTool

    tool = TrufflehogTool()
    findings = tool.parse_output("")
    assert findings == []


@pytest.mark.anyio
async def test_trufflehog_skips_on_cooldown():
    from workers.api_worker.tools.trufflehog_tool import TrufflehogTool

    tool = TrufflehogTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
            headers={},
        )
    assert result.get("skipped_cooldown") is True


# ===================================================================
# Stage 2: auth_testing
# ===================================================================


# ---------------------------------------------------------------------------
# JwtTool tests
# ---------------------------------------------------------------------------

SAMPLE_JWT_TOOL_OUTPUT = """
[+] Algorithm confusion vulnerability found!
[+] Token accepted with "none" algorithm
[+] kid path traversal accepted: ../../../../dev/null
"""


def test_jwt_tool_parse_output():
    from workers.api_worker.tools.jwt_tool import JwtTool
    tool = JwtTool()
    findings = tool.parse_output(SAMPLE_JWT_TOOL_OUTPUT)
    assert len(findings) >= 2
    assert any("none" in f.lower() for f in findings)


def test_jwt_tool_build_command():
    from workers.api_worker.tools.jwt_tool import JwtTool
    tool = JwtTool()
    cmd = tool.build_command(
        token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
        mode="at",
    )
    assert "python3" in cmd or "jwt_tool" in " ".join(cmd)
    assert "-t" in cmd


@pytest.mark.anyio
async def test_jwt_tool_skips_on_cooldown():
    from workers.api_worker.tools.jwt_tool import JwtTool
    tool = JwtTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# OauthTesterTool tests
# ---------------------------------------------------------------------------

def test_oauth_tester_generates_redirect_variants():
    from workers.api_worker.tools.oauth_tester import OauthTesterTool
    tool = OauthTesterTool()
    variants = tool.generate_redirect_uri_variants("https://acme.com/callback")
    assert any("attacker.com" in v for v in variants)
    assert any("/../" in v for v in variants)
    assert len(variants) >= 3


@pytest.mark.anyio
async def test_oauth_tester_skips_on_cooldown():
    from workers.api_worker.tools.oauth_tester import OauthTesterTool
    tool = OauthTesterTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# CorsScannerTool tests
# ---------------------------------------------------------------------------

SAMPLE_CORSCANNER_OUTPUT = json.dumps({
    "results": [
        {"url": "https://acme.com/api/v1/users", "type": "reflect_origin",
         "origin": "https://evil.com", "credentials": True},
        {"url": "https://acme.com/api/v1/data", "type": "null_origin",
         "origin": "null", "credentials": False},
    ]
})


def test_cors_scanner_parse_output():
    from workers.api_worker.tools.cors_scanner import CorsScannerTool
    tool = CorsScannerTool()
    findings = tool.parse_output(SAMPLE_CORSCANNER_OUTPUT)
    assert len(findings) == 2
    assert findings[0]["type"] == "reflect_origin"


@pytest.mark.anyio
async def test_cors_scanner_skips_on_cooldown():
    from workers.api_worker.tools.cors_scanner import CorsScannerTool
    tool = CorsScannerTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ===================================================================
# Stage 3: injection_testing
# ===================================================================


# ---------------------------------------------------------------------------
# IdorTesterTool tests
# ---------------------------------------------------------------------------

def test_idor_tester_detects_path_params():
    from workers.api_worker.tools.idor_tester import IdorTesterTool
    tool = IdorTesterTool()
    assert tool.has_path_params("/api/v1/users/:id") is True
    assert tool.has_path_params("/api/v1/users/{userId}") is True
    assert tool.has_path_params("/api/v1/users") is False


def test_idor_tester_generates_test_ids():
    from workers.api_worker.tools.idor_tester import IdorTesterTool
    tool = IdorTesterTool()
    ids = tool.generate_test_ids()
    assert 1 in ids
    assert len(ids) >= 5


@pytest.mark.anyio
async def test_idor_tester_skips_on_cooldown():
    from workers.api_worker.tools.idor_tester import IdorTesterTool
    tool = IdorTesterTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# MassAssignTesterTool tests
# ---------------------------------------------------------------------------

def test_mass_assign_sensitive_fields():
    from workers.api_worker.tools.mass_assign_tester import SENSITIVE_FIELDS
    assert "role" in SENSITIVE_FIELDS
    assert "is_admin" in SENSITIVE_FIELDS
    assert "permissions" in SENSITIVE_FIELDS
    assert "balance" in SENSITIVE_FIELDS


def test_mass_assign_severity_for_field():
    from workers.api_worker.tools.mass_assign_tester import MassAssignTesterTool
    tool = MassAssignTesterTool()
    assert tool.severity_for_field("role") == "critical"
    assert tool.severity_for_field("is_admin") == "critical"
    assert tool.severity_for_field("balance") == "high"
    assert tool.severity_for_field("verified") == "high"


@pytest.mark.anyio
async def test_mass_assign_skips_on_cooldown():
    from workers.api_worker.tools.mass_assign_tester import MassAssignTesterTool
    tool = MassAssignTesterTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True


# ---------------------------------------------------------------------------
# NosqlmapTool tests
# ---------------------------------------------------------------------------

SAMPLE_NOSQLMAP_OUTPUT = """
[+] MongoDB detected
[+] $ne injection successful on parameter: username
[+] Authentication bypass confirmed
"""


def test_nosqlmap_parse_output():
    from workers.api_worker.tools.nosqlmap_tool import NosqlmapTool
    tool = NosqlmapTool()
    findings = tool.parse_output(SAMPLE_NOSQLMAP_OUTPUT)
    assert len(findings) >= 2
    assert any("injection" in f.lower() for f in findings)


@pytest.mark.anyio
async def test_nosqlmap_skips_on_cooldown():
    from workers.api_worker.tools.nosqlmap_tool import NosqlmapTool
    tool = NosqlmapTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(), target_id=1,
            container_name="test", headers={},
        )
    assert result.get("skipped_cooldown") is True
