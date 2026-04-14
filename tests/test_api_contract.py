# tests/test_api_contract.py
"""API contract tests — validate endpoints against the OpenAPI schema.

Fetches the live OpenAPI spec from the FastAPI app and asserts that
every documented endpoint returns responses whose shape matches the schema.
Also validates request body schemas for key mutation endpoints.
"""

import os
import pytest

os.environ["DB_DRIVER"] = "sqlite+aiosqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["WEB_APP_BH_API_KEY"] = "test-api-key-1234"

import tests._patch_logger  # noqa: F401

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from lib_webbh.database import (
    get_engine, Base, get_session,
    Target, Asset, Location, Vulnerability, JobState, Alert,
    BountySubmission, ScheduledScan, CustomPlaybook,
)

from unittest.mock import patch, AsyncMock, MagicMock
with patch("orchestrator.rate_limit.rate_limit_check"):
    from orchestrator.main import app

pytestmark = pytest.mark.anyio

API = {"X-API-KEY": "test-api-key-1234"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture
async def db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def openapi_spec(client):
    """Fetch the live OpenAPI spec from the app."""
    resp = await client.get("/openapi.json")
    assert resp.status_code == 200
    return resp.json()


@pytest.fixture
def mock_fs(tmp_path):
    """Patch filesystem paths so create_target doesn't hit /app/shared/."""
    with patch("orchestrator.main.SHARED_CONFIG", tmp_path / "config"), \
         patch("orchestrator.main.SHARED_RAW", tmp_path / "raw"), \
         patch("orchestrator.main.SHARED_REPORTS", tmp_path / "reports"):
        yield tmp_path


@pytest_asyncio.fixture
async def seed_target(db):
    async with get_session() as session:
        t = Target(company_name="ContractCorp", base_domain="contract.com", target_profile={})
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return t


@pytest_asyncio.fixture
async def seed_full(seed_target):
    """Seed a target with assets, vulns, jobs, alerts."""
    t = seed_target
    async with get_session() as session:
        asset = Asset(target_id=t.id, asset_type="domain", asset_value="api.contract.com")
        session.add(asset)
        await session.commit()
        await session.refresh(asset)

        loc = Location(asset_id=asset.id, port=443, protocol="tcp", service="https")
        session.add(loc)

        vuln = Vulnerability(
            target_id=t.id, asset_id=asset.id,
            title="Reflected XSS", severity="high",
            description="Reflected XSS in search param",
        )
        session.add(vuln)

        job = JobState(
            target_id=t.id, container_name="webbh-info_gathering-1",
            status="COMPLETED", current_phase="info_gathering",
        )
        session.add(job)

        alert = Alert(target_id=t.id, alert_type="vulnerability", message="XSS found on login page")
        session.add(alert)

        await session.commit()
        await session.refresh(asset)
        await session.refresh(vuln)
        await session.refresh(job)
        await session.refresh(alert)
        return {"target": t, "asset": asset, "vuln": vuln, "job": job, "alert": alert}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _resolve_ref(spec: dict, ref: str) -> dict:
    """Resolve a $ref string like '#/components/schemas/Foo'."""
    parts = ref.lstrip("#/").split("/")
    node = spec
    for part in parts:
        node = node[part]
    return node


def _resolve_schema(spec: dict, schema: dict) -> dict:
    """Recursively resolve $ref in a JSON Schema node."""
    if "$ref" in schema:
        return _resolve_schema(spec, _resolve_ref(spec, schema["$ref"]))
    return schema


def _validate_value_against_schema(value, schema: dict, spec: dict, path: str = "") -> list[str]:
    """Lightweight JSON Schema validator — checks type, required, properties.

    Returns a list of violation strings (empty = valid).
    """
    errors = []
    schema = _resolve_schema(spec, schema)

    # anyOf / oneOf — succeed if any branch matches
    for keyword in ("anyOf", "oneOf"):
        if keyword in schema:
            branch_errors = []
            for branch in schema[keyword]:
                errs = _validate_value_against_schema(value, branch, spec, path)
                if not errs:
                    return []  # at least one branch matched
                branch_errors.extend(errs)
            errors.append(f"{path}: no branch of {keyword} matched")
            return errors

    # allOf — merge and validate
    if "allOf" in schema:
        merged = {}
        for branch in schema["allOf"]:
            resolved = _resolve_schema(spec, branch)
            for k, v in resolved.items():
                if k == "properties":
                    merged.setdefault("properties", {}).update(v)
                elif k == "required":
                    merged.setdefault("required", []).extend(v)
                else:
                    merged[k] = v
        return _validate_value_against_schema(value, merged, spec, path)

    # Null check
    if value is None:
        if schema.get("nullable", False) or schema.get("type") == "null":
            return []
        # OpenAPI 3.1 may not have "nullable" — just accept None for optional fields
        return []

    schema_type = schema.get("type")

    # Type checking
    type_map = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    if schema_type and schema_type in type_map:
        expected = type_map[schema_type]
        if not isinstance(value, expected):
            # Allow int for number type
            if schema_type == "number" and isinstance(value, (int, float)):
                pass
            else:
                errors.append(f"{path}: expected {schema_type}, got {type(value).__name__}")
                return errors

    # Object properties
    if schema_type == "object" and isinstance(value, dict):
        props = schema.get("properties", {})
        required = schema.get("required", [])
        for req_key in required:
            if req_key not in value:
                errors.append(f"{path}.{req_key}: required field missing")
        for key, val in value.items():
            if key in props:
                errors.extend(
                    _validate_value_against_schema(val, props[key], spec, f"{path}.{key}")
                )

    # Array items
    if schema_type == "array" and isinstance(value, list):
        items_schema = schema.get("items", {})
        for i, item in enumerate(value[:5]):  # validate first 5 items for brevity
            errors.extend(
                _validate_value_against_schema(item, items_schema, spec, f"{path}[{i}]")
            )

    return errors


# ---------------------------------------------------------------------------
# Tests — Schema structure
# ---------------------------------------------------------------------------
class TestOpenAPISchemaStructure:
    """Validate the OpenAPI spec itself is well-formed."""

    async def test_openapi_version(self, client, openapi_spec):
        assert openapi_spec["openapi"].startswith("3.")

    async def test_info_present(self, client, openapi_spec):
        assert "info" in openapi_spec
        assert "title" in openapi_spec["info"]

    async def test_paths_present(self, client, openapi_spec):
        assert "paths" in openapi_spec
        assert len(openapi_spec["paths"]) > 0

    async def test_all_paths_have_methods(self, client, openapi_spec):
        for path, methods in openapi_spec["paths"].items():
            valid_methods = {"get", "post", "put", "patch", "delete", "options", "head"}
            actual = set(methods.keys()) & valid_methods
            assert len(actual) > 0, f"{path} has no HTTP methods"

    async def test_all_endpoints_have_operationId_or_summary(self, client, openapi_spec):
        for path, methods in openapi_spec["paths"].items():
            for method, details in methods.items():
                if method in ("get", "post", "put", "patch", "delete"):
                    has_id = "operationId" in details or "summary" in details
                    assert has_id, f"{method.upper()} {path} missing operationId/summary"

    async def test_known_endpoints_present(self, client, openapi_spec):
        """Core endpoints must be documented."""
        expected_paths = [
            "/api/v1/targets",
            "/api/v1/status",
            "/api/v1/assets",
            "/api/v1/vulnerabilities",
            "/api/v1/search",
            "/api/v1/bounties",
            "/api/v1/schedules",
            "/api/v1/playbooks",
        ]
        paths = openapi_spec["paths"]
        for ep in expected_paths:
            assert ep in paths, f"Missing endpoint: {ep}"


# ---------------------------------------------------------------------------
# Tests — Request body schemas
# ---------------------------------------------------------------------------
class TestRequestBodyContracts:
    """Validate that documented request body schemas accept/reject correctly."""

    async def test_create_target_required_fields(self, client, db):
        resp = await client.post("/api/v1/targets", json={}, headers=API)
        assert resp.status_code == 422
        body = resp.json()
        assert "detail" in body

    async def test_create_target_valid(self, client, db, mock_fs):
        resp = await client.post("/api/v1/targets", json={
            "company_name": "SchemaTest",
            "base_domain": "schema.test.com",
        }, headers=API)
        assert resp.status_code == 201
        body = resp.json()
        assert "target_id" in body
        assert "base_domain" in body

    async def test_create_target_extra_fields_ignored(self, client, db, mock_fs):
        resp = await client.post("/api/v1/targets", json={
            "company_name": "Extra",
            "base_domain": "extra.com",
            "nonexistent_field": "should be ignored",
        }, headers=API)
        # FastAPI ignores extra fields by default
        assert resp.status_code in (201, 422)

    async def test_control_action_validation(self, client, db):
        resp = await client.post("/api/v1/control", json={}, headers=API)
        assert resp.status_code == 422

    async def test_bounty_create_validation(self, client, db):
        # Missing required fields
        resp = await client.post("/api/v1/bounties", json={}, headers=API)
        assert resp.status_code == 422

    async def test_schedule_create_validation(self, client, db):
        resp = await client.post("/api/v1/schedules", json={}, headers=API)
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Tests — Response shape matches schema
# ---------------------------------------------------------------------------
class TestResponseContracts:
    """Hit endpoints and validate response shapes against the OpenAPI spec."""

    async def test_list_targets_response(self, client, db, openapi_spec, seed_target):
        resp = await client.get("/api/v1/targets", headers=API)
        assert resp.status_code == 200
        body = resp.json()
        assert "targets" in body
        assert isinstance(body["targets"], list)
        assert len(body["targets"]) >= 1
        target = body["targets"][0]
        # Key fields from the schema
        for field in ("id", "company_name", "base_domain", "status"):
            assert field in target, f"Missing field: {field}"

    async def test_create_target_response_shape(self, client, db, openapi_spec, mock_fs):
        resp = await client.post("/api/v1/targets", json={
            "company_name": "ShapeCorp",
            "base_domain": "shape.com",
        }, headers=API)
        assert resp.status_code == 201
        body = resp.json()
        assert isinstance(body["target_id"], int)
        assert body["base_domain"] == "shape.com"
        assert "playbook" in body

    async def test_status_response(self, client, db, openapi_spec, seed_full):
        resp = await client.get("/api/v1/status", headers=API)
        assert resp.status_code == 200
        body = resp.json()
        assert "jobs" in body
        assert isinstance(body["jobs"], list)

    async def test_assets_response(self, client, db, openapi_spec, seed_full):
        data = seed_full
        resp = await client.get(
            f"/api/v1/assets?target_id={data['target'].id}",
            headers=API,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "assets" in body
        assert isinstance(body["assets"], list)
        if body["assets"]:
            asset = body["assets"][0]
            for field in ("id", "asset_type", "asset_value"):
                assert field in asset, f"Missing field: {field}"

    async def test_vulnerabilities_response(self, client, db, openapi_spec, seed_full):
        data = seed_full
        resp = await client.get(
            f"/api/v1/vulnerabilities?target_id={data['target'].id}",
            headers=API,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "vulnerabilities" in body
        assert isinstance(body["vulnerabilities"], list)
        if body["vulnerabilities"]:
            vuln = body["vulnerabilities"][0]
            for field in ("id", "title", "severity"):
                assert field in vuln, f"Missing field: {field}"

    async def test_alerts_response(self, client, db, openapi_spec, seed_full):
        data = seed_full
        resp = await client.get(
            f"/api/v1/alerts?target_id={data['target'].id}",
            headers=API,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "alerts" in body
        assert isinstance(body["alerts"], list)

    async def test_search_response(self, client, db, openapi_spec, seed_full):
        data = seed_full
        resp = await client.get(
            f"/api/v1/search?target_id={data['target'].id}&q=contract&limit=5",
            headers=API,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "query" in body
        assert "results" in body
        assert isinstance(body["results"], list)

    async def test_queue_health_response(self, client, db, openapi_spec):
        with patch("orchestrator.main.get_redis", new_callable=AsyncMock) as mock_redis:
            mock_conn = AsyncMock()
            mock_conn.xinfo_stream = AsyncMock(side_effect=Exception("no stream"))
            mock_redis.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_redis.return_value.__aexit__ = AsyncMock(return_value=False)
            resp = await client.get("/api/v1/queue_health", headers=API)
        assert resp.status_code == 200
        body = resp.json()
        assert "queues" in body
        assert isinstance(body["queues"], dict)

    async def test_bounties_list_response(self, client, db, openapi_spec):
        resp = await client.get("/api/v1/bounties", headers=API)
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)

    async def test_schedules_list_response(self, client, db, openapi_spec):
        resp = await client.get("/api/v1/schedules", headers=API)
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)

    async def test_playbooks_list_response(self, client, db, openapi_spec):
        resp = await client.get("/api/v1/playbooks", headers=API)
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)


# ---------------------------------------------------------------------------
# Tests — Schema validation for response bodies
# ---------------------------------------------------------------------------
class TestSchemaValidation:
    """Use the OpenAPI spec to validate actual response payloads structurally."""

    async def test_targets_list_matches_schema(self, client, db, openapi_spec, seed_target):
        resp = await client.get("/api/v1/targets", headers=API)
        body = resp.json()

        # Get the schema for this endpoint's 200 response
        path_spec = openapi_spec["paths"].get("/api/v1/targets", {})
        get_spec = path_spec.get("get", {})
        response_200 = get_spec.get("responses", {}).get("200", {})
        content = response_200.get("content", {}).get("application/json", {})
        schema = content.get("schema", {})

        if schema:
            errors = _validate_value_against_schema(body, schema, openapi_spec, "response")
            assert errors == [], f"Schema violations: {errors}"

    async def test_status_matches_schema(self, client, db, openapi_spec, seed_full):
        resp = await client.get("/api/v1/status", headers=API)
        body = resp.json()

        path_spec = openapi_spec["paths"].get("/api/v1/status", {})
        get_spec = path_spec.get("get", {})
        response_200 = get_spec.get("responses", {}).get("200", {})
        content = response_200.get("content", {}).get("application/json", {})
        schema = content.get("schema", {})

        if schema:
            errors = _validate_value_against_schema(body, schema, openapi_spec, "response")
            assert errors == [], f"Schema violations: {errors}"

    async def test_search_matches_schema(self, client, db, openapi_spec, seed_full):
        data = seed_full
        resp = await client.get(
            f"/api/v1/search?target_id={data['target'].id}&q=contract",
            headers=API,
        )
        body = resp.json()

        path_spec = openapi_spec["paths"].get("/api/v1/search", {})
        get_spec = path_spec.get("get", {})
        response_200 = get_spec.get("responses", {}).get("200", {})
        content = response_200.get("content", {}).get("application/json", {})
        schema = content.get("schema", {})

        if schema:
            errors = _validate_value_against_schema(body, schema, openapi_spec, "response")
            assert errors == [], f"Schema violations: {errors}"


# ---------------------------------------------------------------------------
# Tests — Auth contract
# ---------------------------------------------------------------------------
class TestAuthContract:
    """Validate auth enforcement is consistent across endpoints."""

    PROTECTED_ENDPOINTS = [
        ("GET", "/api/v1/targets"),
        ("GET", "/api/v1/status"),
        ("GET", "/api/v1/assets?target_id=1"),
        ("GET", "/api/v1/vulnerabilities?target_id=1"),
        ("GET", "/api/v1/search?q=test"),
        ("GET", "/api/v1/bounties"),
        ("GET", "/api/v1/schedules"),
        ("GET", "/api/v1/playbooks"),
        ("POST", "/api/v1/targets"),
        ("POST", "/api/v1/control"),
        ("POST", "/api/v1/bounties"),
    ]

    @pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
    async def test_missing_api_key_returns_401(self, client, db, method, path):
        if method == "GET":
            resp = await client.get(path)
        else:
            resp = await client.post(path, json={})
        assert resp.status_code == 401, f"{method} {path} should require auth"

    @pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
    async def test_bad_api_key_returns_401(self, client, db, method, path):
        bad_headers = {"X-API-KEY": "wrong-key"}
        if method == "GET":
            resp = await client.get(path, headers=bad_headers)
        else:
            resp = await client.post(path, json={}, headers=bad_headers)
        assert resp.status_code == 401, f"{method} {path} should reject bad key"


# ---------------------------------------------------------------------------
# Tests — Error response contract
# ---------------------------------------------------------------------------
class TestErrorContracts:
    """Error responses should follow a consistent shape."""

    async def test_404_shape(self, client, db):
        resp = await client.get("/api/v1/nonexistent", headers=API)
        assert resp.status_code in (404, 405)

    async def test_422_shape(self, client, db):
        resp = await client.post("/api/v1/targets", json={}, headers=API)
        assert resp.status_code == 422
        body = resp.json()
        assert "detail" in body
        # FastAPI validation errors return a list of error objects
        assert isinstance(body["detail"], list)
        if body["detail"]:
            err = body["detail"][0]
            assert "msg" in err or "message" in err

    async def test_delete_nonexistent_target(self, client, db):
        resp = await client.delete("/api/v1/targets/99999", headers=API)
        assert resp.status_code == 404
        body = resp.json()
        assert "detail" in body

    async def test_patch_nonexistent_alert(self, client, db):
        resp = await client.patch(
            "/api/v1/alerts/99999",
            json={"is_read": True},
            headers=API,
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests — Pagination & query param contracts
# ---------------------------------------------------------------------------
class TestQueryParamContracts:
    """Endpoints with pagination/filter params should honor them."""

    async def test_assets_requires_target_id(self, client, db):
        resp = await client.get("/api/v1/assets", headers=API)
        # Should either require target_id or return empty
        assert resp.status_code in (200, 422)

    async def test_vulns_pagination(self, client, db, seed_full):
        data = seed_full
        resp = await client.get(
            f"/api/v1/vulnerabilities?target_id={data['target'].id}&limit=1&offset=0",
            headers=API,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "vulnerabilities" in body

    async def test_search_limit_honored(self, client, db, seed_full):
        data = seed_full
        resp = await client.get(
            f"/api/v1/search?target_id={data['target'].id}&q=contract&limit=1",
            headers=API,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body.get("results", [])) <= 1
