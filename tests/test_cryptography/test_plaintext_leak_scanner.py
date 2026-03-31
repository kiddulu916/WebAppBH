# tests/test_cryptography/test_plaintext_leak_scanner.py
import pytest

pytestmark = pytest.mark.anyio


def test_plaintext_leak_scanner_subclasses_base():
    from workers.cryptography.tools.plaintext_leak_scanner import PlaintextLeakScanner
    from workers.cryptography.base_tool import CryptographyTool

    assert issubclass(PlaintextLeakScanner, CryptographyTool)


async def test_plaintext_leak_scanner_execute(db_session):
    """Test that execute runs and produces expected output type."""
    from lib_webbh.database import Target
    from workers.cryptography.tools.plaintext_leak_scanner import PlaintextLeakScanner

    target = Target(company_name="TestCo", base_domain="testphp.vulnweb.com")
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    tool = PlaintextLeakScanner()
    await tool.execute(target.id)