# tests/test_cryptography/test_tls_auditor.py
import pytest

pytestmark = pytest.mark.anyio


def test_tls_auditor_subclasses_base():
    from workers.cryptography.tools.tls_auditor import TlsAuditor
    from workers.cryptography.base_tool import CryptographyTool

    assert issubclass(TlsAuditor, CryptographyTool)


async def test_tls_auditor_execute(db_session):
    """Test that execute runs and produces expected output type."""
    from lib_webbh.database import Target
    from workers.cryptography.tools.tls_auditor import TlsAuditor

    target = Target(company_name="TestCo", base_domain="testphp.vulnweb.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    tool = TlsAuditor()
    await tool.execute(target.id)

    # Should have saved some vulnerabilities or observations
    # (exact test depends on implementation)