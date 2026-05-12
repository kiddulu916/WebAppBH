# tests/test_info_gathering_base_tool.py
"""Regression tests for InfoGatheringTool base helpers."""
import json

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.tools.httpx import Httpx


class _Dummy(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs) -> None:
        ...


class TestSaveObservation:
    @pytest.mark.anyio
    async def test_save_observation_accepts_asset_id_keyword(self):
        """Locks the kwarg contract: save_observation(asset_id=..., tech_stack=..., status_code=..., headers=...)."""
        tool = _Dummy()
        with patch("workers.info_gathering.base_tool.get_session") as mock_sess:
            sess = AsyncMock()
            sess.add = MagicMock()
            mock_sess.return_value.__aenter__.return_value = sess
            mock_sess.return_value.__aexit__.return_value = False
            sess.refresh = AsyncMock(side_effect=lambda obs: setattr(obs, "id", 42))
            obs_id = await tool.save_observation(
                asset_id=501,
                tech_stack={"_probe": "banner", "server": "nginx"},
                status_code=200,
                headers={"Server": "nginx"},
            )
        sess.add.assert_called_once()
        sess.commit.assert_awaited_once()
        sess.refresh.assert_awaited_once()
        assert obs_id == 42


class TestHttpxObservationLinkage:
    @pytest.mark.anyio
    async def test_httpx_writes_observation_against_asset_id(self, tmp_path):
        """Httpx must call save_observation with asset_id, not target_id."""
        tool = Httpx()
        line = json.dumps({"url": "https://a.com", "status_code": 200, "title": "T", "tech": ["nginx"]})

        fake = MagicMock()
        fake.name = str(tmp_path / "hosts.txt")
        fake.__enter__ = MagicMock(return_value=fake)
        fake.__exit__ = MagicMock(return_value=False)
        fake.write = MagicMock()

        with patch("workers.info_gathering.tools.httpx.tempfile.NamedTemporaryFile",
                   return_value=fake), \
             patch("workers.info_gathering.tools.httpx.os.path.exists", return_value=False), \
             patch.object(tool, "run_subprocess", new_callable=AsyncMock, return_value=line), \
             patch.object(tool, "save_observation", new_callable=AsyncMock, return_value=1) as save:
            await tool.execute(target_id=1, asset_id=501, host="a.com")

        kwargs = save.call_args.kwargs
        assert "asset_id" in kwargs
        assert kwargs["asset_id"] == 501
        assert "target_id" not in kwargs


from workers.info_gathering.tools.whatweb import WhatWeb


class TestWhatWebObservationLinkage:
    @pytest.mark.anyio
    async def test_whatweb_writes_observation_against_asset_id(self):
        """WhatWeb must call save_observation with asset_id, not target_id."""
        tool = WhatWeb()
        ww_json = json.dumps([{"target": "https://a.com", "plugins": {"Apache": {}}}])
        with patch.object(tool, "run_subprocess", new_callable=AsyncMock, return_value=ww_json):
            with patch.object(tool, "save_observation", new_callable=AsyncMock, return_value=1) as save:
                await tool.execute(target_id=1, asset_id=501, host="a.com", intensity="low")
        kwargs = save.call_args.kwargs
        assert kwargs["asset_id"] == 501
        assert "target_id" not in kwargs

    @pytest.mark.anyio
    async def test_whatweb_high_intensity_adds_aggression_flag(self):
        """intensity=high must append -a 3 to the whatweb argv."""
        tool = WhatWeb()
        ww_json = json.dumps([{"target": "https://a.com", "plugins": {}}])
        with patch.object(tool, "run_subprocess", new_callable=AsyncMock, return_value=ww_json) as sub:
            with patch.object(tool, "save_observation", new_callable=AsyncMock, return_value=1):
                await tool.execute(target_id=1, asset_id=501, host="a.com", intensity="high")
        cmd = sub.call_args.args[0]
        assert cmd[:3] == ["whatweb", "--json", "-"]
        assert "-a" in cmd and "3" in cmd
        assert cmd[-1] == "https://a.com"

    @pytest.mark.anyio
    async def test_whatweb_low_intensity_does_not_add_aggression_flag(self):
        """intensity=low must NOT add -a 3."""
        tool = WhatWeb()
        ww_json = json.dumps([{"target": "https://a.com", "plugins": {}}])
        with patch.object(tool, "run_subprocess", new_callable=AsyncMock, return_value=ww_json) as sub:
            with patch.object(tool, "save_observation", new_callable=AsyncMock, return_value=1):
                await tool.execute(target_id=1, asset_id=501, host="a.com", intensity="low")
        cmd = sub.call_args.args[0]
        assert "-a" not in cmd


class TestSaveLocation:
    @pytest.mark.anyio
    async def test_save_location_inserts_new_row_when_none_exists(self):
        """save_location must create a Location row keyed by (asset_id, port, protocol)."""
        tool = _Dummy()
        with patch("workers.info_gathering.base_tool.get_session") as mock_sess:
            sess = AsyncMock()
            sess.add = MagicMock()
            mock_sess.return_value.__aenter__.return_value = sess
            mock_sess.return_value.__aexit__.return_value = False
            # First execute() returns "no existing row"
            exec_result = MagicMock()
            exec_result.scalar_one_or_none.return_value = None
            sess.execute = AsyncMock(return_value=exec_result)
            sess.refresh = AsyncMock(side_effect=lambda loc: setattr(loc, "id", 9))
            loc_id = await tool.save_location(
                asset_id=501, port=443, protocol="tcp", service="https", state="open",
            )
        sess.add.assert_called_once()
        sess.commit.assert_awaited_once()
        sess.refresh.assert_awaited_once()
        assert loc_id == 9

    @pytest.mark.anyio
    async def test_save_location_updates_existing_row(self):
        """When a row already exists for (asset_id, port, protocol), service/state are updated."""
        from lib_webbh.database import Location
        existing = Location(asset_id=501, port=443, protocol="tcp", service=None, state=None)
        existing.id = 7
        tool = _Dummy()
        with patch("workers.info_gathering.base_tool.get_session") as mock_sess:
            sess = AsyncMock()
            sess.add = MagicMock()
            mock_sess.return_value.__aenter__.return_value = sess
            mock_sess.return_value.__aexit__.return_value = False
            exec_result = MagicMock()
            exec_result.scalar_one_or_none.return_value = existing
            sess.execute = AsyncMock(return_value=exec_result)
            loc_id = await tool.save_location(
                asset_id=501, port=443, protocol="tcp", service="https", state="open",
            )
        sess.add.assert_not_called()
        sess.commit.assert_awaited_once()
        assert loc_id == 7
        assert existing.service == "https"
        assert existing.state == "open"


from contextlib import asynccontextmanager

import sqlalchemy
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from lib_webbh.database import Asset, Base, Target


@pytest.fixture
async def db_session():
    """Fresh in-memory aiosqlite session with the lib_webbh schema."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as sess:
        yield sess
    await engine.dispose()


@pytest.fixture
def patched_get_session(db_session, monkeypatch):
    """Patch get_session in base_tool to yield the test db_session."""
    @asynccontextmanager
    async def fake_session():
        yield db_session
    monkeypatch.setattr("workers.info_gathering.base_tool.get_session", fake_session)
    return db_session


class TestResolveOrCreateAsset:
    @pytest.mark.anyio
    async def test_resolves_existing_subdomain_asset(self, patched_get_session):
        sess = patched_get_session
        t = Target(company_name="X", base_domain="acme.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="subdomain", asset_value="api.acme.com")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)

        tool = _Dummy()
        asset_id = await tool.resolve_or_create_asset(
            t.id, "api.acme.com", base_domain="acme.com",
        )
        assert asset_id == a.id

    @pytest.mark.anyio
    async def test_creates_subdomain_for_unseen_host(self, patched_get_session):
        sess = patched_get_session
        t = Target(company_name="X", base_domain="acme.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)

        tool = _Dummy()
        asset_id = await tool.resolve_or_create_asset(
            t.id, "new.acme.com", base_domain="acme.com",
        )
        row = (await sess.execute(
            sqlalchemy.select(Asset).where(Asset.id == asset_id)
        )).scalar_one()
        assert row.asset_type == "subdomain"
        assert row.asset_value == "new.acme.com"
        assert row.source_tool == "pipeline_preamble"

    @pytest.mark.anyio
    async def test_creates_ip_type_for_ipv4_host(self, patched_get_session):
        sess = patched_get_session
        t = Target(company_name="X", base_domain="acme.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)

        tool = _Dummy()
        asset_id = await tool.resolve_or_create_asset(
            t.id, "203.0.113.10", base_domain="acme.com",
        )
        row = (await sess.execute(
            sqlalchemy.select(Asset).where(Asset.id == asset_id)
        )).scalar_one()
        assert row.asset_type == "ip"

    @pytest.mark.anyio
    async def test_resolves_existing_base_domain_asset(self, patched_get_session):
        sess = patched_get_session
        t = Target(company_name="X", base_domain="acme.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="acme.com")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)

        tool = _Dummy()
        asset_id = await tool.resolve_or_create_asset(
            t.id, "acme.com", base_domain="acme.com",
        )
        assert asset_id == a.id
