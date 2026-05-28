from lib_webbh.playbooks import StageConfig
from lib_webbh.database import Campaign, Vulnerability
import sqlalchemy as sa


def test_stage_config_defaults():
    sc = StageConfig(name="csrf")
    assert sc.out_of_scope is False
    assert sc.chain_exception is False


def test_stage_config_oos_only():
    sc = StageConfig(name="csrf", out_of_scope=True)
    assert sc.out_of_scope is True
    assert sc.chain_exception is False


def test_stage_config_chain_exception():
    sc = StageConfig(name="csrf", out_of_scope=True, chain_exception=True)
    assert sc.out_of_scope is True
    assert sc.chain_exception is True


def test_campaign_has_conditional_stages_column():
    cols = {c.name for c in Campaign.__table__.columns}
    assert "conditional_stages" in cols


def test_vulnerability_has_chain_only_column():
    cols = {c.name for c in Vulnerability.__table__.columns}
    assert "chain_only" in cols


def test_vulnerability_chain_only_index():
    index_names = {idx.name for idx in Vulnerability.__table__.indexes}
    assert "ix_vulns_chain_only" in index_names
