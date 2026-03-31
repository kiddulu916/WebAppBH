# tests/test_cryptography/test_padding_oracle_tester.py
import pytest

pytestmark = pytest.mark.anyio


def test_padding_oracle_tester_subclasses_base():
    from workers.cryptography.tools.padding_oracle_tester import PaddingOracleTester
    from workers.cryptography.base_tool import CryptographyTool

    assert issubclass(PaddingOracleTester, CryptographyTool)


async def test_padding_oracle_tester_execute(db_session):
    """Test that execute runs and produces expected output type."""
    from lib_webbh.database import Target
    from workers.cryptography.tools.padding_oracle_tester import PaddingOracleTester

    target = Target(company_name="TestCo", base_domain="testphp.vulnweb.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    tool = PaddingOracleTester()
    await tool.execute(target.id)