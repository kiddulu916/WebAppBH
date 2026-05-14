"""Stage 2 (web_server_fingerprint) integration tests.

Each test exercises the full pipeline preamble → tools → aggregator → DB writes
path with in-memory aiosqlite + mocked subprocess / aiohttp. Fixture ``db_engine``
patches all ``get_session`` references so every ORM write goes to the same SQLite
in-memory DB.
"""
from __future__ import annotations

import re
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aioresponses import aioresponses
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from lib_webbh.database import Asset, Base, Location, Observation, Target, Vulnerability, JobState
from workers.info_gathering.base_tool import InfoGatheringTool
from tests.fixtures.stage2.cloudflare_responses import (
    CF_404_BODY,
    CF_HEADERS,
    HTTPX_OUT,
    TLSX_OUT,
    WAFW00F_OUT,
    WHATWEB_OUT,
)


# ---------------------------------------------------------------------------
# Shared DB fixture
# ---------------------------------------------------------------------------

@pytest.fixture
async def db_engine(monkeypatch, tmp_path):
    """File-backed aiosqlite DB (NullPool) with all get_session paths patched.

    NullPool gives each session its own connection so concurrent probes don't
    contend on the same SQLite connection object (StaticPool would serialize
    every await point and corrupt session state).
    """
    db_file = tmp_path / "stage2_test.db"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_file}",
        poolclass=NullPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # WAL mode lets concurrent readers coexist with a writer
        await conn.execute(text("PRAGMA journal_mode=WAL"))
    Session = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def fake_get_session():
        async with Session() as s:
            yield s

    monkeypatch.setattr("workers.info_gathering.base_tool.get_session", fake_get_session)
    monkeypatch.setattr("workers.info_gathering.pipeline.get_session", fake_get_session)
    monkeypatch.setattr("lib_webbh.pipeline_checkpoint.get_session", fake_get_session)
    monkeypatch.setattr("lib_webbh.get_session", fake_get_session)
    monkeypatch.setattr("lib_webbh.database.get_session", fake_get_session)

    yield engine, Session
    await engine.dispose()


# ---------------------------------------------------------------------------
# Subprocess dispatcher (used by I1, I2, I10 …)
# ---------------------------------------------------------------------------

def _make_subprocess_dispatch(overrides: dict | None = None) -> AsyncMock:
    """Return an AsyncMock for ``run_subprocess`` that dispatches by command name."""
    defaults = {
        "httpx": HTTPX_OUT,
        "tlsx": TLSX_OUT,
        "wafw00f": WAFW00F_OUT,
        "whatweb": WHATWEB_OUT,
    }
    table = {**defaults, **(overrides or {})}

    async def _dispatch(cmd, **_):
        return table.get(cmd[0], "")

    return AsyncMock(side_effect=_dispatch)


# ---------------------------------------------------------------------------
# I1 — happy path: Cloudflare-fronted target
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_full_path_cloudflare_target(db_engine):
    """Probe set writes observations + locations + summary + at least one vuln."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Acme", base_domain="acme.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="subdomain", asset_value="api.acme.com")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": True,
         "config": {"fingerprint_intensity": "medium"}},
    ]}]}
    target_obj = MagicMock(id=target_id, base_domain="acme.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    _any_url = re.compile(r"https://api\.acme\.com.*")

    with patch.object(InfoGatheringTool, "run_subprocess", new=_make_subprocess_dispatch()):
        with patch("workers.info_gathering.tools.header_order_probe.HeaderOrderProbe._raw_get",
                   new=AsyncMock(return_value="HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\n")):
            with aioresponses() as m:
                m.get("https://api.acme.com/", status=200, body="", headers=CF_HEADERS, repeat=True)
                m.get(_any_url, status=404, body=CF_404_BODY, repeat=True)
                m.options("https://api.acme.com/", status=200, headers={"Allow": "GET,HEAD,POST"}, repeat=True)
                m.head("https://api.acme.com/", status=200, headers={}, repeat=True)
                m.add("https://api.acme.com/", method="PROPFIND", status=405, headers={}, repeat=True)
                m.add("https://api.acme.com/", method="TRACE", status=405, headers={}, repeat=True)
                with patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
                    await pipeline.run(
                        target_obj, scope_manager, playbook=playbook,
                        host="api.acme.com",
                    )

    async with Session() as sess:
        obs_rows = (
            await sess.execute(select(Observation).where(Observation.asset_id == asset_id))
        ).scalars().all()
        probes = {o.tech_stack.get("_probe") for o in obs_rows if o.tech_stack}
        assert "summary" in probes, f"missing summary probe; got: {probes}"
        assert "banner" in probes, f"missing banner probe; got: {probes}"
        assert "tls" in probes, f"missing tls probe; got: {probes}"

        summary = next(o for o in obs_rows if o.tech_stack.get("_probe") == "summary")
        assert summary.tech_stack["fingerprint"]["edge"]["vendor"] == "Cloudflare"

        locs = (
            await sess.execute(select(Location).where(Location.asset_id == asset_id))
        ).scalars().all()
        assert {l.port for l in locs} >= {80, 443}

        vulns = (
            await sess.execute(select(Vulnerability).where(Vulnerability.asset_id == asset_id))
        ).scalars().all()
        titles = {v.title for v in vulns}
        assert "Framework disclosure via X-Powered-By" in titles


# ---------------------------------------------------------------------------
# I2 — happy path: bare nginx origin (no CDN/edge layer)
# ---------------------------------------------------------------------------

NGINX_HEADERS = {
    "Server": "nginx/1.25.3",
    "Content-Type": "text/html",
}
NGINX_HTTPX_OUT = "\n".join([
    '{"url":"https://origin.example.com:443","port":"443","status_code":200,"tech":[]}',
])
NGINX_TLSX_OUT = '{"host":"origin.example.com","tls_version":"tls12","issuer_cn":"Let\'s Encrypt","subject_an":["origin.example.com"],"alpn":["http/1.1"]}'
NGINX_WAFW00F_OUT = '{"detected":false,"firewall":""}'
NGINX_WHATWEB_OUT = '[{"target":"https://origin.example.com","plugins":{"nginx":{}}}]'


@pytest.mark.anyio
async def test_stage2_full_path_bare_nginx_target(db_engine):
    """Origin-server slot = nginx; edge slot empty; no X-Powered-By vuln."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="subdomain", asset_value="origin.example.com")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": True,
         "config": {"fingerprint_intensity": "low"}},
    ]}]}
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    _any_url = re.compile(r"https://origin\.example\.com.*")
    dispatch = _make_subprocess_dispatch({
        "httpx": NGINX_HTTPX_OUT,
        "tlsx": NGINX_TLSX_OUT,
        "wafw00f": NGINX_WAFW00F_OUT,
        "whatweb": NGINX_WHATWEB_OUT,
    })

    with patch.object(InfoGatheringTool, "run_subprocess", new=dispatch):
        with patch("workers.info_gathering.tools.header_order_probe.HeaderOrderProbe._raw_get",
                   new=AsyncMock(return_value="HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n")):
            with aioresponses() as m:
                m.get("https://origin.example.com/", status=200, body="<html>nginx</html>",
                      headers=NGINX_HEADERS, repeat=True)
                m.get(_any_url, status=404, body="<center>nginx</center>", repeat=True)
                m.options("https://origin.example.com/", status=200,
                          headers={"Allow": "GET,HEAD"}, repeat=True)
                m.head("https://origin.example.com/", status=200, headers={}, repeat=True)
                with patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
                    await pipeline.run(
                        target_obj, scope_manager, playbook=playbook,
                        host="origin.example.com",
                    )

    async with Session() as sess:
        obs_rows = (
            await sess.execute(select(Observation).where(Observation.asset_id == asset_id))
        ).scalars().all()
        probes = {o.tech_stack.get("_probe") for o in obs_rows if o.tech_stack}
        assert "summary" in probes

        summary = next(o for o in obs_rows if o.tech_stack.get("_probe") == "summary")
        fp = summary.tech_stack["fingerprint"]
        assert fp["origin_server"]["vendor"] == "nginx", f"expected nginx; got {fp['origin_server']}"
        assert fp["edge"]["vendor"] is None, f"unexpected edge vendor: {fp['edge']['vendor']}"

        vulns = (
            await sess.execute(select(Vulnerability).where(Vulnerability.asset_id == asset_id))
        ).scalars().all()
        titles = {v.title for v in vulns}
        assert "Framework disclosure via X-Powered-By" not in titles
