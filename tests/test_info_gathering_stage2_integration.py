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


# ---------------------------------------------------------------------------
# Shared helper: run stage 2 for a host and return (Session, asset_id)
# ---------------------------------------------------------------------------

async def _run_stage2(
    Session, target_id: int, host: str, base_domain: str,
    intensity: str = "low",
    extra_subprocess: dict | None = None,
    push_mock: AsyncMock | None = None,
    rate_limiter=None,
) -> int:
    """Run stage 2 for *host* under *target_id*; returns asset_id."""
    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": True,
         "config": {"fingerprint_intensity": intensity}},
    ]}]}
    target_obj = MagicMock(id=target_id, base_domain=base_domain)
    scope_mgr = MagicMock(_in_scope_patterns=set())

    _any_url = re.compile(rf"https://{re.escape(host)}.*")
    dispatch = _make_subprocess_dispatch(extra_subprocess)
    _push = push_mock or AsyncMock()

    with patch.object(InfoGatheringTool, "run_subprocess", new=dispatch):
        with patch("workers.info_gathering.tools.header_order_probe.HeaderOrderProbe._raw_get",
                   new=AsyncMock(return_value=f"HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\n")):
            with aioresponses() as m:
                m.get(f"https://{host}/", status=200, body="", headers=CF_HEADERS, repeat=True)
                m.get(_any_url, status=404, body=CF_404_BODY, repeat=True)
                m.options(f"https://{host}/", status=200, headers={"Allow": "GET,HEAD"}, repeat=True)
                m.head(f"https://{host}/", status=200, headers={}, repeat=True)
                m.add(f"https://{host}/", method="PROPFIND", status=405, headers={}, repeat=True)
                m.add(f"https://{host}/", method="TRACE", status=405, headers={}, repeat=True)
                m.add(f"https://{host}/", method="ASDF", status=400, headers={}, repeat=True)
                m.add(f"https://{host}/", method="DELETE", status=405, headers={}, repeat=True)
                m.add(f"https://{host}/", method="PUT", status=405, headers={}, repeat=True)
                with patch("workers.info_gathering.pipeline.push_task", new=_push):
                    await pipeline.run(
                        target_obj, scope_mgr, playbook=playbook,
                        host=host, rate_limiter=rate_limiter,
                    )

    # resolve the asset_id
    async with Session() as sess:
        from sqlalchemy import func
        row = (await sess.execute(
            select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_value == host,
            )
        )).scalar_one()
        return row.id


# ---------------------------------------------------------------------------
# I3 — location dedup on rerun
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_writes_locations_for_alive_ports(db_engine):
    """Running stage 2 twice doesn't duplicate Location rows for the same ports."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="LocTest", base_domain="loc.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        target_id = t.id

    await _run_stage2(Session, target_id, "sub.loc.test", "loc.test")
    await _run_stage2(Session, target_id, "sub.loc.test", "loc.test")

    async with Session() as sess:
        asset_id = (await sess.execute(
            select(Asset.id).where(Asset.target_id == target_id, Asset.asset_value == "sub.loc.test")
        )).scalar_one()
        locs = (await sess.execute(select(Location).where(Location.asset_id == asset_id))).scalars().all()
        ports = [l.port for l in locs]
        assert len(ports) == len(set(ports)), f"duplicate location ports: {ports}"
        assert set(ports) >= {80, 443}


# ---------------------------------------------------------------------------
# I4 — SSE event shape
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_emits_sse_event_with_stats(db_engine):
    """push_task must receive a STAGE_COMPLETE event with correct stats shape."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="SSETest", base_domain="sse.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        target_id = t.id

    push_mock = AsyncMock()
    await _run_stage2(Session, target_id, "sse.test", "sse.test", push_mock=push_mock)

    stage_events = [
        call.args[1] for call in push_mock.call_args_list
        if call.args[0] == f"events:{target_id}"
        and call.args[1].get("event") == "STAGE_COMPLETE"
        and call.args[1].get("stage") == "web_server_fingerprint"
    ]
    assert len(stage_events) == 1, f"expected 1 STAGE_COMPLETE event; got {push_mock.call_args_list}"
    stats = stage_events[0]["stats"]
    assert isinstance(stats.get("probes"), int) and stats["probes"] > 0
    assert stats.get("summary_written") is True
    assert isinstance(stats.get("vulns"), int)


# ---------------------------------------------------------------------------
# I5 — resume: pre-seeded checkpoint causes stage 2 to be skipped
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_resume_after_crash(db_engine):
    """If last_completed_stage == 'web_server_fingerprint', stage 2 is not re-run."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="ResumeTest", base_domain="resume.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        # Pre-seed JobState marking stage 2 already completed.
        job = JobState(
            target_id=t.id, container_name="info_gathering",
            status="RUNNING", last_completed_stage="web_server_fingerprint",
        )
        sess.add(job)
        await sess.commit()
        target_id = t.id

    await _run_stage2(Session, target_id, "resume.test", "resume.test")

    async with Session() as sess:
        # No observations should exist — stage was skipped due to checkpoint.
        obs_count = (await sess.execute(
            select(Observation).where(Observation.tech_stack["_probe"].as_string() == "summary")
        )).scalars().all()
        assert len(obs_count) == 0, "stage 2 should have been skipped on resume"


# ---------------------------------------------------------------------------
# I6 — rate limiter acquire called
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_respects_rate_limiter(db_engine):
    """The rate_limiter.acquire() is called at least once during stage 2."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="RLTest", base_domain="rl.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        target_id = t.id

    rate_limiter = MagicMock()
    rate_limiter.acquire = AsyncMock()

    await _run_stage2(Session, target_id, "rl.test", "rl.test", rate_limiter=rate_limiter)

    assert rate_limiter.acquire.await_count >= 1, "rate_limiter.acquire never awaited"


# ---------------------------------------------------------------------------
# I7 — scope classification runs when scope_manager has patterns
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_scope_classification_with_patterns(db_engine):
    """When scope_manager has patterns, _classify_pending_assets is invoked."""
    from lib_webbh.deep_classifier import DeepClassifier

    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="ScopeTest", base_domain="scope.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": True},
    ]}]}
    target_obj = MagicMock(id=target_id, base_domain="scope.test")
    scope_mgr = MagicMock()
    scope_mgr._in_scope_patterns = {"scope.test"}
    host = "scope.test"

    classify_mock = AsyncMock()

    with patch.object(InfoGatheringTool, "run_subprocess", new=_make_subprocess_dispatch()):
        with patch("workers.info_gathering.tools.header_order_probe.HeaderOrderProbe._raw_get",
                   new=AsyncMock(return_value="HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\n")):
            with patch.object(pipeline, "_classify_pending_assets", new=classify_mock):
                with aioresponses() as m:
                    m.get(f"https://{host}/", status=200, body="", headers=CF_HEADERS, repeat=True)
                    m.get(re.compile(rf"https://{re.escape(host)}.*"), status=404, body=CF_404_BODY, repeat=True)
                    m.options(f"https://{host}/", status=200, headers={"Allow": "GET,HEAD"}, repeat=True)
                    m.head(f"https://{host}/", status=200, headers={}, repeat=True)
                    with patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
                        await pipeline.run(target_obj, scope_mgr, playbook=playbook, host=host)

    classify_mock.assert_awaited_once_with(scope_mgr)


# ---------------------------------------------------------------------------
# I8 — disabled stage produces no observations
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_playbook_disables_stage(db_engine):
    """When web_server_fingerprint is disabled in the playbook, no probes run."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="DisabledTest", base_domain="disabled.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="disabled.test")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": False},
    ]}]}
    target_obj = MagicMock(id=target_id, base_domain="disabled.test")
    scope_mgr = MagicMock(_in_scope_patterns=set())

    with patch.object(InfoGatheringTool, "run_subprocess", new=_make_subprocess_dispatch()):
        with patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
            await pipeline.run(target_obj, scope_mgr, playbook=playbook, host="disabled.test")

    async with Session() as sess:
        obs = (await sess.execute(
            select(Observation).where(Observation.asset_id == asset_id)
        )).scalars().all()
        assert len(obs) == 0, f"expected no observations; got {len(obs)}"


# ---------------------------------------------------------------------------
# I9 — high intensity writes expanded method_probe observation
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_intensity_high_writes_method_quirks_rows(db_engine):
    """High intensity adds ASDF/DELETE/PUT to method_probe Observation."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="HighTest", base_domain="high.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        target_id = t.id

    asset_id = await _run_stage2(
        Session, target_id, "high.test", "high.test", intensity="high",
    )

    async with Session() as sess:
        obs_rows = (await sess.execute(
            select(Observation).where(
                Observation.asset_id == asset_id,
                Observation.tech_stack["_probe"].as_string() == "method_probe",
            )
        )).scalars().all()
        assert obs_rows, "no method_probe observation written"
        results = obs_rows[0].tech_stack.get("results", {})
        sent_methods = set(results.keys())
        assert {"ASDF", "DELETE", "PUT"} <= sent_methods, (
            f"high-intensity methods missing; sent: {sent_methods}"
        )


# ---------------------------------------------------------------------------
# I10 — partial failure: summary carries partial=True
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_partial_failure_writes_summary_with_partial_flag(db_engine):
    """When some probes error, summary Observation has partial=True."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="PartialTest", base_domain="partial.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="partial.test")
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
    target_obj = MagicMock(id=target_id, base_domain="partial.test")
    scope_mgr = MagicMock(_in_scope_patterns=set())

    async def _dispatch_failing(cmd, **_):
        if cmd[0] in ("tlsx", "wafw00f"):
            raise RuntimeError("simulated tool failure")
        return {
            "httpx": HTTPX_OUT,
            "whatweb": WHATWEB_OUT,
        }.get(cmd[0], "")

    with patch.object(InfoGatheringTool, "run_subprocess",
                      new=AsyncMock(side_effect=_dispatch_failing)):
        with patch("workers.info_gathering.tools.header_order_probe.HeaderOrderProbe._raw_get",
                   new=AsyncMock(return_value="HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\n")):
            with aioresponses() as m:
                m.get("https://partial.test/", status=200, body="", headers=CF_HEADERS, repeat=True)
                m.get(re.compile(r"https://partial\.test.*"), status=404, body=CF_404_BODY, repeat=True)
                m.options("https://partial.test/", status=200, headers={"Allow": "GET,HEAD"}, repeat=True)
                m.head("https://partial.test/", status=200, headers={}, repeat=True)
                with patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
                    await pipeline.run(
                        target_obj, scope_mgr, playbook=playbook, host="partial.test",
                    )

    async with Session() as sess:
        summary_rows = (await sess.execute(
            select(Observation).where(
                Observation.asset_id == asset_id,
                Observation.tech_stack["_probe"].as_string() == "summary",
            )
        )).scalars().all()
        assert summary_rows, "no summary observation written"
        assert summary_rows[0].tech_stack["partial"] is True


# ---------------------------------------------------------------------------
# I11 — vuln evidence links to the correct probe observation
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_info_leak_vulnerability_links_evidence(db_engine):
    """X-Powered-By vuln's evidence.probe_obs_id points to the banner Observation."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="EvidTest", base_domain="evid.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="evid.test")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    asset_id = await _run_stage2(Session, target_id, "evid.test", "evid.test")

    async with Session() as sess:
        vuln = (await sess.execute(
            select(Vulnerability).where(
                Vulnerability.asset_id == asset_id,
                Vulnerability.title == "Framework disclosure via X-Powered-By",
            )
        )).scalar_one_or_none()
        assert vuln is not None, "expected X-Powered-By vuln"
        probe_obs_id = (vuln.evidence or {}).get("probe_obs_id")
        assert probe_obs_id is not None, "evidence.probe_obs_id is missing"

        banner_obs = (await sess.execute(
            select(Observation).where(
                Observation.id == probe_obs_id,
                Observation.tech_stack["_probe"].as_string() == "banner",
            )
        )).scalar_one_or_none()
        assert banner_obs is not None, f"probe_obs_id={probe_obs_id} does not resolve to a banner obs"


# ---------------------------------------------------------------------------
# I12 — subject asset resolution is idempotent
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_subject_asset_resolution_idempotent(db_engine):
    """Two pipeline runs against the same host produce exactly one Asset row."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="IdempTest", base_domain="idemp.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        target_id = t.id

    await _run_stage2(Session, target_id, "idemp.test", "idemp.test")
    await _run_stage2(Session, target_id, "idemp.test", "idemp.test")

    async with Session() as sess:
        asset_rows = (await sess.execute(
            select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_value == "idemp.test",
            )
        )).scalars().all()
        assert len(asset_rows) == 1, f"expected 1 asset; got {len(asset_rows)}"


# ---------------------------------------------------------------------------
# I13 — IP host creates ip-typed asset
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_ip_host_uses_ip_asset_type(db_engine):
    """A pipeline run against an IP address resolves an ip-typed Asset."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="IPTest", base_domain="ip.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        target_id = t.id

    ip_httpx = '{"url":"https://203.0.113.10:443","port":"443","status_code":200,"tech":[]}'

    await _run_stage2(
        Session, target_id, "203.0.113.10", "ip.test",
        extra_subprocess={"httpx": ip_httpx},
    )

    async with Session() as sess:
        asset = (await sess.execute(
            select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_value == "203.0.113.10",
            )
        )).scalar_one_or_none()
        assert asset is not None, "no asset created for IP host"
        assert asset.asset_type == "ip", f"expected ip; got {asset.asset_type}"


# ---------------------------------------------------------------------------
# I14 — default intensity when playbook omits the field
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage2_default_intensity_when_playbook_omits_field(db_engine):
    """When fingerprint_intensity is absent from the playbook, intensity defaults to 'low'."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="IntDefault", base_domain="intdef.test")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="intdef.test")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    # No "config" key → fingerprint_intensity absent
    playbook = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": True},
    ]}]}
    target_obj = MagicMock(id=target_id, base_domain="intdef.test")
    scope_mgr = MagicMock(_in_scope_patterns=set())

    with patch.object(InfoGatheringTool, "run_subprocess", new=_make_subprocess_dispatch()):
        with patch("workers.info_gathering.tools.header_order_probe.HeaderOrderProbe._raw_get",
                   new=AsyncMock(return_value="HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\n")):
            with aioresponses() as m:
                m.get("https://intdef.test/", status=200, body="", headers=CF_HEADERS, repeat=True)
                m.get(re.compile(r"https://intdef\.test.*"), status=404, body=CF_404_BODY, repeat=True)
                m.options("https://intdef.test/", status=200, headers={"Allow": "GET,HEAD"}, repeat=True)
                m.head("https://intdef.test/", status=200, headers={}, repeat=True)
                with patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
                    await pipeline.run(
                        target_obj, scope_mgr, playbook=playbook, host="intdef.test",
                    )

    async with Session() as sess:
        summary = (await sess.execute(
            select(Observation).where(
                Observation.asset_id == asset_id,
                Observation.tech_stack["_probe"].as_string() == "summary",
            )
        )).scalar_one_or_none()
        assert summary is not None, "no summary observation"
        assert summary.tech_stack.get("intensity") == "low", (
            f"expected intensity='low'; got {summary.tech_stack.get('intensity')}"
        )
