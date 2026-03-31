# M2: Infrastructure Services Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Stand up the Traffic Proxy (mitmproxy-based) and Callback Server (self-hosted OOB listener) as Docker containers, and add proxy/callback helper methods to a shared mixin for use in worker base_tool classes.

**Architecture:** Two independent Docker services. Traffic Proxy wraps mitmproxy with a Rule Manager REST API on port 8081. Callback Server runs HTTP (9090), DNS (9053), and TCP (9443) listeners with a polling API (9091). Both are opt-in — tools explicitly route through them when needed.

**Tech Stack:** Python 3.10, mitmproxy, aiohttp (Rule Manager + Callback APIs), asyncio, Docker

**Design docs:** `docs/plans/design/2026-03-29-restructure-01-infrastructure-services.md`, `docs/plans/design/2026-03-29-restructure-02-safety-policy.md`

---

## Task 1: Scaffold Proxy Directory

**Files:**
- Create: `workers/proxy/__init__.py`
- Create: `workers/proxy/addon.py` (empty placeholder)
- Create: `workers/proxy/rule_manager.py` (empty placeholder)
- Create: `workers/proxy/main.py` (empty placeholder)
- Create: `workers/proxy/requirements.txt`
- Create: `tests/test_proxy/__init__.py`

**Step 1: Create directories and files**

```bash
mkdir -p workers/proxy tests/test_proxy
touch workers/proxy/__init__.py workers/proxy/addon.py
touch workers/proxy/rule_manager.py workers/proxy/main.py
touch tests/test_proxy/__init__.py
```

**Step 2: Create requirements.txt**

```txt
# workers/proxy/requirements.txt
mitmproxy>=10.0
aiohttp>=3.9
```

**Step 3: Commit**

```bash
git add workers/proxy/ tests/test_proxy/
git commit -m "chore(proxy): scaffold traffic proxy directory structure"
```

---

## Task 2: Rule Manager — Data Model & Storage

**Files:**
- Create: `workers/proxy/rule_store.py`
- Test: `tests/test_proxy/test_rule_store.py`

**Step 1: Write the failing test**

```python
# tests/test_proxy/test_rule_store.py
import pytest


def test_add_rule():
    from workers.proxy.rule_store import RuleStore

    store = RuleStore()
    rule_id = store.add_rule({
        "match": {"url_pattern": "*/api/login*"},
        "transform": {"type": "replace_param", "param": "username", "value": "admin"},
    })

    assert rule_id is not None
    assert store.get_rule(rule_id) is not None


def test_list_rules():
    from workers.proxy.rule_store import RuleStore

    store = RuleStore()
    store.add_rule({"match": {"url_pattern": "*"}, "transform": {"type": "inject_header", "header": "X-Test", "value": "1"}})
    store.add_rule({"match": {"url_pattern": "*/admin*"}, "transform": {"type": "strip_header", "header": "Cookie"}})

    rules = store.list_rules()
    assert len(rules) == 2


def test_delete_rule():
    from workers.proxy.rule_store import RuleStore

    store = RuleStore()
    rule_id = store.add_rule({"match": {"url_pattern": "*"}, "transform": {"type": "delay", "ms": 500}})
    assert store.delete_rule(rule_id) is True
    assert store.get_rule(rule_id) is None
    assert store.delete_rule("nonexistent") is False


def test_match_url():
    from workers.proxy.rule_store import RuleStore

    store = RuleStore()
    store.add_rule({"match": {"url_pattern": "*/api/*"}, "transform": {"type": "inject_header", "header": "X-Proxy", "value": "true"}})

    matches = store.match_url("https://target.com/api/users")
    assert len(matches) == 1

    matches = store.match_url("https://target.com/static/style.css")
    assert len(matches) == 0
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_proxy/test_rule_store.py -v`

**Step 3: Write rule_store.py**

```python
# workers/proxy/rule_store.py
import fnmatch
import uuid
from typing import Optional


class RuleStore:
    """In-memory rule storage for the traffic proxy."""

    def __init__(self):
        self._rules: dict[str, dict] = {}

    def add_rule(self, rule: dict) -> str:
        rule_id = str(uuid.uuid4())[:8]
        self._rules[rule_id] = {**rule, "id": rule_id}
        return rule_id

    def get_rule(self, rule_id: str) -> Optional[dict]:
        return self._rules.get(rule_id)

    def list_rules(self) -> list[dict]:
        return list(self._rules.values())

    def delete_rule(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    def match_url(self, url: str) -> list[dict]:
        matches = []
        for rule in self._rules.values():
            pattern = rule.get("match", {}).get("url_pattern", "*")
            if fnmatch.fnmatch(url, pattern):
                matches.append(rule)
        return matches
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/proxy/rule_store.py tests/test_proxy/test_rule_store.py
git commit -m "feat(proxy): add RuleStore for in-memory proxy rule management"
```

---

## Task 3: Rule Manager — REST API

**Files:**
- Modify: `workers/proxy/rule_manager.py`
- Test: `tests/test_proxy/test_rule_manager.py`

**Step 1: Write the failing test**

```python
# tests/test_proxy/test_rule_manager.py
import pytest
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from aiohttp import web

pytestmark = pytest.mark.anyio


async def test_rule_manager_crud():
    from workers.proxy.rule_manager import create_app

    app = create_app()

    from aiohttp.test_utils import TestClient, TestServer
    async with TestClient(TestServer(app)) as client:
        # POST — create rule
        resp = await client.post("/rules", json={
            "match": {"url_pattern": "*/api/*"},
            "transform": {"type": "inject_header", "header": "X-Test", "value": "1"},
        })
        assert resp.status == 201
        data = await resp.json()
        rule_id = data["id"]

        # GET — list rules
        resp = await client.get("/rules")
        assert resp.status == 200
        rules = await resp.json()
        assert len(rules) == 1

        # DELETE — remove rule
        resp = await client.delete(f"/rules/{rule_id}")
        assert resp.status == 200

        # Verify deleted
        resp = await client.get("/rules")
        rules = await resp.json()
        assert len(rules) == 0
```

**Step 2: Run test, verify fail.**

**Step 3: Write rule_manager.py**

```python
# workers/proxy/rule_manager.py
from aiohttp import web
from .rule_store import RuleStore

_store = RuleStore()


async def post_rule(request):
    data = await request.json()
    rule_id = _store.add_rule(data)
    return web.json_response({"id": rule_id}, status=201)


async def get_rules(request):
    return web.json_response(_store.list_rules())


async def delete_rule(request):
    rule_id = request.match_info["rule_id"]
    if _store.delete_rule(rule_id):
        return web.json_response({"deleted": rule_id})
    return web.json_response({"error": "not found"}, status=404)


def create_app(store=None):
    global _store
    if store:
        _store = store
    app = web.Application()
    app.router.add_post("/rules", post_rule)
    app.router.add_get("/rules", get_rules)
    app.router.add_delete("/rules/{rule_id}", delete_rule)
    return app
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/proxy/rule_manager.py tests/test_proxy/test_rule_manager.py
git commit -m "feat(proxy): add Rule Manager REST API (POST/GET/DELETE /rules)"
```

---

## Task 4: Scaffold Callback Server Directory

**Files:**
- Create: `workers/callback/__init__.py`
- Create: `workers/callback/listeners.py` (empty placeholder)
- Create: `workers/callback/callback_store.py` (empty placeholder)
- Create: `workers/callback/api.py` (empty placeholder)
- Create: `workers/callback/main.py` (empty placeholder)
- Create: `workers/callback/requirements.txt`
- Create: `tests/test_callback/__init__.py`

**Step 1: Create directories**

```bash
mkdir -p workers/callback tests/test_callback
touch workers/callback/__init__.py workers/callback/listeners.py
touch workers/callback/callback_store.py workers/callback/api.py
touch workers/callback/main.py tests/test_callback/__init__.py
```

**Step 2: Create requirements.txt**

```txt
# workers/callback/requirements.txt
aiohttp>=3.9
```

**Step 3: Commit**

```bash
git add workers/callback/ tests/test_callback/
git commit -m "chore(callback): scaffold callback server directory structure"
```

---

## Task 5: Callback Store

**Files:**
- Create: `workers/callback/callback_store.py`
- Test: `tests/test_callback/test_callback_store.py`

**Step 1: Write the failing test**

```python
# tests/test_callback/test_callback_store.py
import pytest


def test_register_callback():
    from workers.callback.callback_store import CallbackStore

    store = CallbackStore()
    cb_id = store.register(protocols=["http", "dns"])

    assert cb_id is not None
    cb = store.get(cb_id)
    assert cb["protocols"] == ["http", "dns"]
    assert cb["interactions"] == []


def test_record_interaction():
    from workers.callback.callback_store import CallbackStore

    store = CallbackStore()
    cb_id = store.register(protocols=["http"])

    store.record_interaction(cb_id, {
        "protocol": "http",
        "source_ip": "10.0.0.1",
        "data": "GET /callback/test HTTP/1.1",
    })

    cb = store.get(cb_id)
    assert len(cb["interactions"]) == 1
    assert cb["interactions"][0]["protocol"] == "http"


def test_cleanup_callback():
    from workers.callback.callback_store import CallbackStore

    store = CallbackStore()
    cb_id = store.register(protocols=["http"])
    assert store.cleanup(cb_id) is True
    assert store.get(cb_id) is None
    assert store.cleanup("nonexistent") is False
```

**Step 2: Run test, verify fail.**

**Step 3: Write callback_store.py**

```python
# workers/callback/callback_store.py
import uuid
from datetime import datetime, timezone
from typing import Optional


class CallbackStore:
    """In-memory storage for registered callbacks and their interactions."""

    def __init__(self):
        self._callbacks: dict[str, dict] = {}

    def register(self, protocols: list[str] | None = None) -> str:
        cb_id = str(uuid.uuid4())[:12]
        self._callbacks[cb_id] = {
            "id": cb_id,
            "protocols": protocols or ["http"],
            "interactions": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        return cb_id

    def get(self, cb_id: str) -> Optional[dict]:
        return self._callbacks.get(cb_id)

    def record_interaction(self, cb_id: str, interaction: dict) -> bool:
        cb = self._callbacks.get(cb_id)
        if cb is None:
            return False
        interaction["timestamp"] = datetime.now(timezone.utc).isoformat()
        cb["interactions"].append(interaction)
        return True

    def cleanup(self, cb_id: str) -> bool:
        return self._callbacks.pop(cb_id, None) is not None
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/callback/callback_store.py tests/test_callback/test_callback_store.py
git commit -m "feat(callback): add CallbackStore for OOB interaction tracking"
```

---

## Task 6: Callback Polling API

**Files:**
- Modify: `workers/callback/api.py`
- Test: `tests/test_callback/test_api.py`

**Step 1: Write the failing test**

```python
# tests/test_callback/test_api.py
import pytest

pytestmark = pytest.mark.anyio


async def test_callback_api_register_and_poll():
    from workers.callback.api import create_app
    from aiohttp.test_utils import TestClient, TestServer

    app = create_app()
    async with TestClient(TestServer(app)) as client:
        # Register
        resp = await client.post("/callbacks", json={"protocols": ["http", "dns"]})
        assert resp.status == 201
        data = await resp.json()
        cb_id = data["id"]

        # Poll — no interactions yet
        resp = await client.get(f"/callbacks/{cb_id}")
        assert resp.status == 200
        data = await resp.json()
        assert data["interactions"] == []

        # Simulate an interaction arriving (via internal record endpoint)
        resp = await client.post(f"/callbacks/{cb_id}/interaction", json={
            "protocol": "http",
            "source_ip": "10.0.0.1",
            "data": "GET / HTTP/1.1",
        })
        assert resp.status == 200

        # Poll again — one interaction
        resp = await client.get(f"/callbacks/{cb_id}")
        data = await resp.json()
        assert len(data["interactions"]) == 1

        # Cleanup
        resp = await client.delete(f"/callbacks/{cb_id}")
        assert resp.status == 200
```

**Step 2: Run test, verify fail.**

**Step 3: Write api.py**

```python
# workers/callback/api.py
from aiohttp import web
from .callback_store import CallbackStore

_store = CallbackStore()


async def register_callback(request):
    data = await request.json()
    cb_id = _store.register(protocols=data.get("protocols"))
    return web.json_response({"id": cb_id}, status=201)


async def poll_callback(request):
    cb_id = request.match_info["cb_id"]
    cb = _store.get(cb_id)
    if cb is None:
        return web.json_response({"error": "not found"}, status=404)
    return web.json_response(cb)


async def record_interaction(request):
    cb_id = request.match_info["cb_id"]
    data = await request.json()
    if _store.record_interaction(cb_id, data):
        return web.json_response({"recorded": True})
    return web.json_response({"error": "not found"}, status=404)


async def delete_callback(request):
    cb_id = request.match_info["cb_id"]
    if _store.cleanup(cb_id):
        return web.json_response({"deleted": cb_id})
    return web.json_response({"error": "not found"}, status=404)


def create_app(store=None):
    global _store
    if store:
        _store = store
    app = web.Application()
    app.router.add_post("/callbacks", register_callback)
    app.router.add_get("/callbacks/{cb_id}", poll_callback)
    app.router.add_post("/callbacks/{cb_id}/interaction", record_interaction)
    app.router.add_delete("/callbacks/{cb_id}", delete_callback)
    return app
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/callback/api.py tests/test_callback/test_api.py
git commit -m "feat(callback): add polling API for callback server"
```

---

## Task 7: Infrastructure Mixin for Worker Base Tools

**Files:**
- Create: `shared/lib_webbh/infra_mixin.py`
- Test: `tests/test_infra_mixin.py`

**Step 1: Write the failing test**

```python
# tests/test_infra_mixin.py
import pytest
from unittest.mock import AsyncMock, patch

pytestmark = pytest.mark.anyio


def test_mixin_has_proxy_methods():
    from lib_webbh.infra_mixin import InfrastructureMixin

    assert hasattr(InfrastructureMixin, "request_via_proxy")
    assert hasattr(InfrastructureMixin, "request_direct")


def test_mixin_has_callback_methods():
    from lib_webbh.infra_mixin import InfrastructureMixin

    assert hasattr(InfrastructureMixin, "register_callback")
    assert hasattr(InfrastructureMixin, "check_callback")
    assert hasattr(InfrastructureMixin, "cleanup_callback")


def test_mixin_has_credential_methods():
    from lib_webbh.infra_mixin import InfrastructureMixin

    assert hasattr(InfrastructureMixin, "get_tester_session")
    assert hasattr(InfrastructureMixin, "get_target_user")
    assert hasattr(InfrastructureMixin, "validate_target_user")
```

**Step 2: Run test, verify fail.**

**Step 3: Write infra_mixin.py**

```python
# shared/lib_webbh/infra_mixin.py
"""Infrastructure mixin providing proxy, callback, and credential helpers.

Worker base_tool classes inherit from this mixin to get access to
shared infrastructure services.
"""

import json
import os
from pathlib import Path
from typing import Optional


class InfrastructureMixin:
    """Mixin for worker base tools. Provides proxy, callback, credential access."""

    _proxy_url = os.environ.get("PROXY_URL", "http://proxy:8080")
    _callback_api = os.environ.get("CALLBACK_API", "http://callback:9091")

    # -- Proxy helpers --

    async def request_via_proxy(self, http_client, method, url, **kwargs):
        """Route a request through the traffic proxy."""
        kwargs.setdefault("proxy", self._proxy_url)
        return await http_client.request(method, url, **kwargs)

    async def request_direct(self, http_client, method, url, **kwargs):
        """Send a request directly, bypassing the proxy."""
        kwargs.pop("proxy", None)
        return await http_client.request(method, url, **kwargs)

    # -- Callback helpers --

    async def register_callback(self, http_client, protocols=None):
        """Register a new callback with the callback server."""
        resp = await http_client.post(
            f"{self._callback_api}/callbacks",
            json={"protocols": protocols or ["http"]},
        )
        data = await resp.json()
        return data["id"]

    async def check_callback(self, http_client, callback_id, timeout=30, poll_interval=2):
        """Poll the callback server for interactions."""
        import asyncio

        elapsed = 0
        while elapsed < timeout:
            resp = await http_client.get(f"{self._callback_api}/callbacks/{callback_id}")
            data = await resp.json()
            if data.get("interactions"):
                return data["interactions"]
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        return []

    async def cleanup_callback(self, http_client, callback_id):
        """Delete a callback registration."""
        await http_client.delete(f"{self._callback_api}/callbacks/{callback_id}")

    # -- Credential helpers --

    def _load_credentials(self, target_id: int) -> Optional[dict]:
        """Load credentials from config file."""
        creds_path = Path(f"shared/config/{target_id}/credentials.json")
        if creds_path.exists():
            return json.loads(creds_path.read_text())
        return None

    async def get_tester_session(self, target_id: int) -> Optional[dict]:
        """Get the Tester credentials for authenticated testing."""
        creds = self._load_credentials(target_id)
        if creds and "tester" in creds:
            return creds["tester"]
        return None

    def get_target_user(self, target_id: int) -> Optional[dict]:
        """Get the Testing User identifiers (no password)."""
        creds = self._load_credentials(target_id)
        if creds and "testing_user" in creds:
            user = creds["testing_user"]
            return {
                "username": user.get("username"),
                "email": user.get("email"),
                "profile_url": user.get("profile_url"),
            }
        return None

    def validate_target_user(self, target_id: int, identifier: str) -> bool:
        """Check if an identifier matches the Testing User."""
        user = self.get_target_user(target_id)
        if not user:
            return False
        return identifier in (user.get("username"), user.get("email"))
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add shared/lib_webbh/infra_mixin.py tests/test_infra_mixin.py
git commit -m "feat(lib): add InfrastructureMixin with proxy, callback, credential helpers"
```

---

## Task 8: Dockerfiles for Proxy & Callback

**Files:**
- Create: `docker/Dockerfile.proxy`
- Create: `docker/Dockerfile.callback`
- Modify: `docker-compose.yml`

**Step 1: Write Dockerfile.proxy**

```dockerfile
# docker/Dockerfile.proxy
FROM python:3.10-slim

RUN pip install mitmproxy>=10.0 aiohttp>=3.9

COPY workers/proxy/ /app/workers/proxy/

WORKDIR /app

# Proxy on 8080, Rule Manager API on 8081
EXPOSE 8080 8081

CMD ["python", "-m", "workers.proxy.main"]
```

**Step 2: Write Dockerfile.callback**

```dockerfile
# docker/Dockerfile.callback
FROM python:3.10-slim

RUN pip install aiohttp>=3.9

COPY workers/callback/ /app/workers/callback/

WORKDIR /app

# HTTP listener 9090, Polling API 9091, DNS 9053, TCP 9443
EXPOSE 9090 9091 9053 9443

CMD ["python", "-m", "workers.callback.main"]
```

**Step 3: Add docker-compose entries**

```yaml
  proxy:
    build:
      context: .
      dockerfile: docker/Dockerfile.proxy
    ports:
      - "8080:8080"
      - "8081:8081"
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 512M
    networks:
      - webbh_net

  callback:
    build:
      context: .
      dockerfile: docker/Dockerfile.callback
    ports:
      - "9090:9090"
      - "9091:9091"
      - "9053:9053/udp"
      - "9443:9443"
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 256M
    networks:
      - webbh_net
```

**Step 4: Commit**

```bash
git add docker/Dockerfile.proxy docker/Dockerfile.callback docker-compose.yml
git commit -m "feat(infra): add Dockerfiles and compose entries for proxy and callback server"
```

---

## Task 9: Full Regression

**Step 1: Run all tests**

Run: `pytest tests/ -v --tb=short`
Expected: All PASS

**Step 2: Verify Docker builds**

Run: `docker compose build proxy callback`
Expected: Both images build successfully

**Step 3: Commit if fixups needed**
