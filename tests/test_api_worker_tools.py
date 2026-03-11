"""Tests for api_worker Stage 1 tools."""

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
