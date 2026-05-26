"""Unit tests for AccountProvisionTester (WSTG-IDNT-03)."""
import json
from unittest.mock import AsyncMock, patch

import pytest

from workers.identity_mgmt.tools.account_provision_tester import AccountProvisionTester


@pytest.fixture
def tester():
    return AccountProvisionTester()


def test_parse_output_returns_list_of_dicts(tester):
    payload = json.dumps([
        {"title": "Account creation without authentication", "description": "POST /api/admin/users returned 201", "severity": "critical", "data": {"endpoint": "/api/admin/users"}},
        {"title": "No rate limiting on provisioning endpoint", "description": "/api/users no rate limit", "severity": "medium", "data": {"endpoint": "/api/users"}},
    ])
    result = tester.parse_output(payload)
    assert len(result) == 2
    assert result[0]["severity"] == "critical"
    assert result[1]["severity"] == "medium"


def test_parse_output_returns_empty_on_invalid_json(tester):
    result = tester.parse_output("not json")
    assert result == []


def test_parse_output_returns_empty_on_blank(tester):
    result = tester.parse_output("")
    assert result == []


def test_build_command_returns_python3_list(tester):
    class FakeTarget:
        target_value = "https://example.com"
    cmd = tester.build_command(FakeTarget())
    assert cmd[0] == "python3"
    assert cmd[1] == "-c"
    assert isinstance(cmd[2], str)
    assert "found_provision_endpoints" in cmd[2]


def test_build_command_injects_base_url(tester):
    class FakeTarget:
        target_value = "https://target.example.com"
    cmd = tester.build_command(FakeTarget())
    assert "https://target.example.com" in cmd[2]


def test_build_command_prepends_https_for_bare_domain(tester):
    class FakeTarget:
        target_value = "target.example.com"
    cmd = tester.build_command(FakeTarget())
    assert "https://target.example.com" in cmd[2]


def test_build_command_injects_tester_credentials(tester):
    class FakeTarget:
        target_value = "https://example.com"
    credentials = {
        "tester": {"username": "attacker", "password": "pass1", "auth_type": "form", "login_url": "https://example.com/login"},
        "testing_user": {"username": "victim", "email": "victim@example.com", "password": "pass2"},
    }
    cmd = tester.build_command(FakeTarget(), credentials=credentials)
    assert "attacker" in cmd[2]
    assert "victim" in cmd[2]


def test_build_command_idor_block_present(tester):
    class FakeTarget:
        target_value = "https://example.com"
    cmd = tester.build_command(FakeTarget())
    assert "Two-account IDOR tests skipped" in cmd[2]


@pytest.mark.asyncio
async def test_execute_enriches_credentials_with_testing_user(tester):
    """execute() must merge testing_user creds before calling build_command."""
    tester_creds = {"username": "atk", "password": "p1", "auth_type": "form"}
    testing_user_creds = {"username": "vict", "email": "v@x.com", "password": "p2"}

    combined_seen = {}

    def capture_build(target, credentials=None):
        combined_seen.update(credentials or {})
        return ["python3", "-c", "import json; print(json.dumps([]))"]

    class FakeTarget:
        target_value = "https://example.com"

    class FakeScopeManager:
        pass

    with patch.object(tester, "build_command", side_effect=capture_build), \
         patch.object(tester, "get_testing_user_credentials", new=AsyncMock(return_value=testing_user_creds)), \
         patch.object(tester, "check_cooldown", new=AsyncMock(return_value=False)), \
         patch("workers.identity_mgmt.tools.account_provision_tester.get_session") as mock_session, \
         patch("workers.identity_mgmt.tools.account_provision_tester.push_task", new=AsyncMock()), \
         patch("workers.identity_mgmt.base_tool.push_task", new=AsyncMock()), \
         patch("workers.identity_mgmt.base_tool.get_session") as mock_base_session:

        from unittest.mock import MagicMock

        # Build a session mock where execute() returns an object with scalar_one_or_none() -> None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session = AsyncMock()
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        mock_db_session.add = MagicMock()
        mock_db_session.commit = AsyncMock()

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_db_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session.return_value = mock_ctx
        mock_base_session.return_value = mock_ctx

        await tester.execute(
            target=FakeTarget(),
            scope_manager=FakeScopeManager(),
            target_id=1,
            container_name="identity_mgmt",
            credentials=tester_creds,
        )

    assert combined_seen.get("tester") == tester_creds
    assert combined_seen.get("testing_user") == testing_user_creds
