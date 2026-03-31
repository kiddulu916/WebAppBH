# tests/test_cryptography/test_algorithm_auditor.py
import pytest

pytestmark = pytest.mark.anyio


def test_algorithm_auditor_subclasses_base():
    from workers.cryptography.tools.algorithm_auditor import AlgorithmAuditor
    from workers.cryptography.base_tool import CryptographyTool

    assert issubclass(AlgorithmAuditor, CryptographyTool)


async def test_algorithm_auditor_execute(db_session):
    """Test that execute runs and produces expected output type."""
    from lib_webbh.database import Target
    from workers.cryptography.tools.algorithm_auditor import AlgorithmAuditor

    target = Target(company_name="TestCo", base_domain="testphp.vulnweb.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    tool = AlgorithmAuditor()
    await tool.execute(target.id)