import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


# ---------------------------------------------------------------------------
# Unit tests — Webanalyze tool wrapper
# ---------------------------------------------------------------------------


def test_webanalyze_name():
    from workers.recon_core.tools.webanalyze import Webanalyze
    assert Webanalyze.name == "webanalyze"


def test_webanalyze_is_light():
    from workers.recon_core.tools.webanalyze import Webanalyze
    from workers.recon_core.concurrency import WeightClass
    assert Webanalyze.weight_class == WeightClass.LIGHT


def test_webanalyze_build_command():
    from workers.recon_core.tools.webanalyze import Webanalyze
    tool = Webanalyze()
    tool._input_file = "/tmp/hosts.txt"
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert cmd == [
        "webanalyze", "-hosts", "/tmp/hosts.txt",
        "-json", "-silent", "-crawl", "1",
    ]


def test_webanalyze_parse_output_valid():
    from workers.recon_core.tools.webanalyze import Webanalyze
    tool = Webanalyze()
    line1 = json.dumps({
        "hostname": "a.example.com",
        "matches": [
            {"app_name": "nginx"},
            {"app_name": "jQuery"},
        ],
    })
    line2 = json.dumps({
        "hostname": "b.example.com",
        "matches": [
            {"app_name": "Apache"},
        ],
    })
    output = f"{line1}\n{line2}\n"
    results = tool.parse_output(output)
    assert len(results) == 2
    assert results[0] == {"host": "a.example.com", "tech": ["nginx", "jQuery"]}
    assert results[1] == {"host": "b.example.com", "tech": ["Apache"]}


def test_webanalyze_parse_output_empty_matches():
    from workers.recon_core.tools.webanalyze import Webanalyze
    tool = Webanalyze()
    line = json.dumps({"hostname": "empty.example.com", "matches": []})
    results = tool.parse_output(line)
    assert results == []


def test_webanalyze_parse_output_bad_json():
    from workers.recon_core.tools.webanalyze import Webanalyze
    tool = Webanalyze()
    results = tool.parse_output("not json\n{broken")
    assert results == []


# ---------------------------------------------------------------------------
# Integration tests — tech merge via _process_dict_result
# ---------------------------------------------------------------------------


@pytest.fixture
async def db_setup():
    """Set up in-memory SQLite with schema and return target_id."""
    from lib_webbh.database import Base, get_engine, get_session, Asset, Target

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with get_session() as session:
        target = Target(company_name="Test", base_domain="example.com")
        session.add(target)
        await session.commit()
        await session.refresh(target)
        target_id = target.id

        asset = Asset(
            target_id=target_id,
            asset_type="domain",
            asset_value="a.example.com",
            source_tool="subfinder",
        )
        session.add(asset)
        await session.commit()

    yield target_id

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.mark.anyio
async def test_tech_merge_new(db_setup):
    """First tech insertion should return True (new)."""
    from workers.recon_core.base_tool import ReconTool
    from lib_webbh.database import get_session, Asset
    from sqlalchemy import select

    target_id = db_setup
    scope_result = MagicMock(in_scope=True, normalized="a.example.com", asset_type="domain", path=None)
    scope_manager = MagicMock()
    scope_manager.is_in_scope.return_value = scope_result
    log = MagicMock()

    # Use a concrete subclass to call _process_dict_result
    class DummyTool(ReconTool):
        name = "dummy"
        weight_class = MagicMock()
        def build_command(self, target, headers=None):
            return []
        def parse_output(self, stdout):
            return []

    tool = DummyTool()
    item = {"host": "a.example.com", "tech": ["nginx", "jQuery"]}
    result = await tool._process_dict_result(item, scope_manager, target_id, log)
    assert result is True

    async with get_session() as session:
        stmt = select(Asset).where(Asset.asset_value == "a.example.com")
        res = await session.execute(stmt)
        asset = res.scalar_one()
        assert set(asset.tech) == {"nginx", "jQuery"}


@pytest.mark.anyio
async def test_tech_merge_dedup(db_setup):
    """Inserting same tech again should return False (duplicate)."""
    from workers.recon_core.base_tool import ReconTool
    from lib_webbh.database import get_session, Asset
    from sqlalchemy import select

    target_id = db_setup
    scope_result = MagicMock(in_scope=True, normalized="a.example.com", asset_type="domain", path=None)
    scope_manager = MagicMock()
    scope_manager.is_in_scope.return_value = scope_result
    log = MagicMock()

    class DummyTool(ReconTool):
        name = "dummy"
        weight_class = MagicMock()
        def build_command(self, target, headers=None):
            return []
        def parse_output(self, stdout):
            return []

    tool = DummyTool()

    # First insert
    item = {"host": "a.example.com", "tech": ["nginx"]}
    await tool._process_dict_result(item, scope_manager, target_id, log)

    # Same tech again — should be False
    result = await tool._process_dict_result(item, scope_manager, target_id, log)
    assert result is False


@pytest.mark.anyio
async def test_tech_merge_union(db_setup):
    """Inserting overlapping tech should merge via set union."""
    from workers.recon_core.base_tool import ReconTool
    from lib_webbh.database import get_session, Asset
    from sqlalchemy import select

    target_id = db_setup
    scope_result = MagicMock(in_scope=True, normalized="a.example.com", asset_type="domain", path=None)
    scope_manager = MagicMock()
    scope_manager.is_in_scope.return_value = scope_result
    log = MagicMock()

    class DummyTool(ReconTool):
        name = "dummy"
        weight_class = MagicMock()
        def build_command(self, target, headers=None):
            return []
        def parse_output(self, stdout):
            return []

    tool = DummyTool()

    await tool._process_dict_result(
        {"host": "a.example.com", "tech": ["nginx", "jQuery"]},
        scope_manager, target_id, log,
    )
    result = await tool._process_dict_result(
        {"host": "a.example.com", "tech": ["jQuery", "React"]},
        scope_manager, target_id, log,
    )
    assert result is True

    async with get_session() as session:
        stmt = select(Asset).where(Asset.asset_value == "a.example.com")
        res = await session.execute(stmt)
        asset = res.scalar_one()
        assert set(asset.tech) == {"nginx", "jQuery", "React"}


@pytest.mark.anyio
async def test_tech_out_of_scope(db_setup):
    """Out-of-scope host should return None."""
    from workers.recon_core.base_tool import ReconTool

    target_id = db_setup
    scope_result = MagicMock(in_scope=False)
    scope_manager = MagicMock()
    scope_manager.is_in_scope.return_value = scope_result
    log = MagicMock()

    class DummyTool(ReconTool):
        name = "dummy"
        weight_class = MagicMock()
        def build_command(self, target, headers=None):
            return []
        def parse_output(self, stdout):
            return []

    tool = DummyTool()
    result = await tool._process_dict_result(
        {"host": "evil.com", "tech": ["nginx"]},
        scope_manager, target_id, log,
    )
    assert result is None
