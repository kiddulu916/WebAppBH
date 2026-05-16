"""Stage 7 (map_execution_paths) integration tests.

Exercises the full path: pipeline _fetch_ws_seeds → asyncio.gather(Katana, Hakrawler)
→ ExecutionPathAnalyzer.write_summary → DB writes → SSE STAGE_COMPLETE event.

Uses aiosqlite for DB (NullPool, WAL), subprocess mocked via patch.object on
InfoGatheringTool.run_subprocess.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import json

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from lib_webbh.database import Asset, Base, Observation, Target
from workers.info_gathering.base_tool import InfoGatheringTool


# ---------------------------------------------------------------------------
# Shared DB fixture
# ---------------------------------------------------------------------------

@pytest.fixture
async def db_engine(monkeypatch, tmp_path):
    db_file = tmp_path / "stage7_test.db"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_file}",
        poolclass=NullPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("PRAGMA journal_mode=WAL"))
    Session = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def fake_get_session():
        async with Session() as s:
            yield s

    monkeypatch.setattr("workers.info_gathering.base_tool.get_session", fake_get_session)
    monkeypatch.setattr("workers.info_gathering.pipeline.get_session", fake_get_session)
    monkeypatch.setattr("workers.info_gathering.tools.execution_path_analyzer.get_session", fake_get_session)
    monkeypatch.setattr("workers.info_gathering.tools.form_mapper.get_session", fake_get_session)
    monkeypatch.setattr("lib_webbh.pipeline_checkpoint.get_session", fake_get_session)
    monkeypatch.setattr("lib_webbh.get_session", fake_get_session)
    monkeypatch.setattr("lib_webbh.database.get_session", fake_get_session)

    yield engine, Session
    await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_playbook(stage_name: str = "map_execution_paths", enabled: bool = True,
                   intensity: str = "low") -> dict:
    """Return a minimal playbook enabling only the named stage.

    intensity is placed under web_server_fingerprint (where _get_intensity reads it).
    """
    return {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": False,
         "config": {"fingerprint_intensity": intensity}},
        {"name": stage_name, "enabled": enabled,
         "config": {}},
    ]}]}


def _katana_output(*urls: str) -> str:
    return "\n".join(json.dumps({"url": u}) for u in urls)


# ---------------------------------------------------------------------------
# I1 — happy path: crawl writes summary Observation
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_full_path_writes_summary_observation(db_engine):
    """Crawl + analyzer writes exactly one summary Observation for the subject asset."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Acme", base_domain="acme.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="acme.com")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="acme.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    katana_out = _katana_output(
        "https://acme.com/page",
        "https://acme.com/api/v1/users",
        "https://acme.com/login",
    )
    hakrawler_out = "https://acme.com/about\nhttps://acme.com/contact\n"

    def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        return hakrawler_out

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="acme.com")

    async with Session() as sess:
        obs_rows = (
            await sess.execute(
                select(Observation).where(Observation.asset_id == asset_id)
            )
        ).scalars().all()

        summary_rows = [o for o in obs_rows if o.tech_stack and o.tech_stack.get("_probe") == "execution_paths"]
        assert len(summary_rows) == 1, f"expected 1 summary obs, got {len(summary_rows)}"

        summary = summary_rows[0]
        assert summary.asset_id == asset_id
        assert summary.tech_stack["total_paths"] > 0
        assert "categories" in summary.tech_stack


# ---------------------------------------------------------------------------
# I2 — WebSocket seeds are queried and passed to Katana
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_ws_seeds_queried_and_passed_to_katana(db_engine):
    """A websocket Asset in the DB must appear as a -u arg in Katana's command."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        ws = Asset(target_id=t.id, asset_type="websocket", asset_value="wss://example.com/ws")
        sess.add_all([a, ws])
        await sess.commit()
        await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    captured_cmds: list[list[str]] = []

    async def _dispatch(cmd, **kwargs):
        captured_cmds.append(list(cmd))
        return ""

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    katana_cmds = [c for c in captured_cmds if c and c[0] == "katana"]
    assert katana_cmds, "Katana was never called"
    katana_cmd_str = " ".join(katana_cmds[0])
    assert "wss://example.com/ws" in katana_cmd_str, (
        f"WS seed not in Katana command: {katana_cmd_str}"
    )


# ---------------------------------------------------------------------------
# I3 — Out-of-scope URLs are not saved
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_scope_violations_not_saved(db_engine):
    """URLs that fail scope_check must not appear as Asset rows in the DB."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")

    scope_manager = MagicMock(_in_scope_patterns={"example.com"})
    scope_manager.classify = MagicMock(side_effect=lambda url: MagicMock(
        classification="in-scope" if "example.com" in url else "out-of-scope"
    ))

    katana_out = _katana_output("https://evil.com/page", "https://example.com/safe")
    hakrawler_out = "https://evil.com/other\n"

    async def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        return hakrawler_out

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    async with Session() as sess:
        all_assets = (
            await sess.execute(select(Asset).where(Asset.target_id == target_id))
        ).scalars().all()
        asset_values = {a.asset_value for a in all_assets}
        assert "https://evil.com/page" not in asset_values
        assert "https://evil.com/other" not in asset_values
        assert "https://example.com/safe" in asset_values


# ---------------------------------------------------------------------------
# I4 — SSE event includes paths_found stat
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_sse_event_includes_paths_found(db_engine):
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    events_published: list[tuple[str, dict]] = []

    async def mock_push_task(stream, payload):
        events_published.append((stream, payload))

    katana_out = _katana_output("https://example.com/p1", "https://example.com/p2")

    async def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        return ""

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock(side_effect=mock_push_task)):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    stage7_events = [
        payload for stream, payload in events_published
        if stream == f"events:{target_id}"
        and payload.get("event") == "STAGE_COMPLETE"
        and payload.get("stage") == "map_execution_paths"
    ]
    assert stage7_events, "No STAGE_COMPLETE event for map_execution_paths"
    stats = stage7_events[0]["stats"]
    assert "paths_found" in stats
    assert stats["paths_found"] >= 2


# ---------------------------------------------------------------------------
# I5 — Intensity medium → depth 3 in Katana command
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_intensity_medium_depth_3_in_katana_cmd(db_engine):
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    # intensity is read from web_server_fingerprint stage config by _get_intensity()
    playbook = _make_playbook(intensity="medium")
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    captured: list[list[str]] = []

    async def _dispatch(cmd, **kwargs):
        captured.append(list(cmd))
        return ""

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    katana_cmds = [c for c in captured if c and c[0] == "katana"]
    assert katana_cmds
    cmd = katana_cmds[0]
    assert cmd[cmd.index("-d") + 1] == "3"


# ---------------------------------------------------------------------------
# I6 — Partial summary when Hakrawler fails
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_partial_summary_when_hakrawler_fails(db_engine):
    """If Hakrawler times out, summary has partial=True; Katana results preserved."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    katana_out = _katana_output("https://example.com/page")

    async def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        # Hakrawler raises TimeoutError; its execute() catches this and returns
        # CrawlResult(tool="hakrawler", error="hakrawler timed out")
        raise TimeoutError("hakrawler timed out")

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    async with Session() as sess:
        obs_rows = (
            await sess.execute(
                select(Observation).where(Observation.asset_id == asset_id)
            )
        ).scalars().all()
        summaries = [o for o in obs_rows if o.tech_stack and o.tech_stack.get("_probe") == "execution_paths"]
        assert summaries, "No summary observation written"
        summary = summaries[0]
        assert summary.tech_stack.get("partial") is True
        assert summary.tech_stack["tool_breakdown"]["hakrawler"]["errored"] is True
        assert summary.tech_stack["tool_breakdown"]["katana"]["errored"] is False
        assert summary.tech_stack["total_paths"] >= 1


# ---------------------------------------------------------------------------
# I7 — wss:// URL discovered during crawl saved as websocket asset type
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_ws_urls_saved_as_websocket_asset_type(db_engine):
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    katana_out = _katana_output("wss://example.com/realtime")

    async def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        return ""

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    async with Session() as sess:
        ws_assets = (
            await sess.execute(
                select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "websocket",
                )
            )
        ).scalars().all()
        ws_values = {a.asset_value for a in ws_assets}
        assert "wss://example.com/realtime" in ws_values


# ---------------------------------------------------------------------------
# I8 — FormMapper has no URL cap
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_no_url_cap_on_form_mapper(db_engine):
    """FormMapper must process more than 20 pre-existing URL assets.

    FormMapper queries asset_type='url', so seed 25 url-type assets.
    """
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="BigSite", base_domain="bigsite.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        # FormMapper queries asset_type='url' (see form_mapper.py line 64)
        assets = [
            Asset(target_id=t.id, asset_type="url", asset_value=f"https://bigsite.com/page{i}")
            for i in range(25)
        ]
        sess.add_all(assets)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.tools.form_mapper import FormMapper

    tool = FormMapper()
    target_obj = MagicMock(base_domain="bigsite.com")
    processed_urls: list[str] = []

    async def mock_fetch_html(url: str) -> str:
        processed_urls.append(url)
        return ""  # no forms; just count pages visited

    with patch.object(tool, "_fetch_html", side_effect=mock_fetch_html):
        await tool.execute(target_id=target_id, target=target_obj)

    # 26 total: 1 base domain + 25 url assets
    assert len(processed_urls) > 20, (
        f"FormMapper only processed {len(processed_urls)} URLs; URL cap may still be present"
    )


# ---------------------------------------------------------------------------
# I9 — Custom headers passed through to Katana
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_headers_passed_to_katana(db_engine):
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    captured: list[list[str]] = []

    async def _dispatch(cmd, **kwargs):
        captured.append(list(cmd))
        return ""

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(
            target_obj, scope_manager,
            headers={"Cookie": "session=abc123"},
            playbook=playbook,
            host="example.com",
        )

    katana_cmds = [c for c in captured if c and c[0] == "katana"]
    assert katana_cmds
    katana_str = " ".join(katana_cmds[0])
    assert "Cookie: session=abc123" in katana_str


# ---------------------------------------------------------------------------
# I10 — Dedup: same URL from both crawlers → single Asset row
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_dedup_does_not_create_duplicate_assets(db_engine):
    """The DB unique constraint must prevent duplicate Asset rows for the same URL."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    shared_url = "https://example.com/shared-page"
    katana_out = _katana_output(shared_url)
    hakrawler_out = f"{shared_url}\n"

    async def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        return hakrawler_out

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    async with Session() as sess:
        rows = (
            await sess.execute(
                select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_value == shared_url,
                )
            )
        ).scalars().all()
        assert len(rows) == 1, f"Expected 1 Asset row for {shared_url}, got {len(rows)}"
