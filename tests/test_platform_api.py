"""Tests for bug bounty platform API integration (4 platforms)."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Tests for base classes
# ---------------------------------------------------------------------------

class TestBaseClasses:
    def test_scope_entry_dataclass(self):
        from lib_webbh.platform_api.base import ScopeEntry
        entry = ScopeEntry(
            asset_type="domain",
            asset_value="*.acme.com",
            eligible_for_bounty=True,
            max_severity="critical",
        )
        assert entry.asset_type == "domain"
        assert entry.eligible_for_bounty is True

    def test_submission_result_dataclass(self):
        from lib_webbh.platform_api.base import SubmissionResult
        result = SubmissionResult(
            external_id="H1-12345",
            status="new",
            platform_url="https://hackerone.com/reports/12345",
        )
        assert result.external_id == "H1-12345"

    def test_platform_client_is_abstract(self):
        from lib_webbh.platform_api.base import PlatformClient
        with pytest.raises(TypeError):
            PlatformClient()

    def test_platform_clients_registry(self):
        from lib_webbh.platform_api import PLATFORM_CLIENTS
        assert "hackerone" in PLATFORM_CLIENTS
        assert "bugcrowd" in PLATFORM_CLIENTS
        assert "intigriti" in PLATFORM_CLIENTS
        assert "yeswehack" in PLATFORM_CLIENTS


# ---------------------------------------------------------------------------
# Helper to mock httpx responses
# ---------------------------------------------------------------------------

def _mock_httpx_response(json_data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.json = MagicMock(return_value=json_data)
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# HackerOne
# ---------------------------------------------------------------------------

class TestHackerOneClient:
    async def test_import_scope(self):
        from lib_webbh.platform_api.hackerone import HackerOneClient

        mock_resp = _mock_httpx_response({
            "relationships": {
                "structured_scopes": {
                    "data": [
                        {
                            "attributes": {
                                "asset_type": "URL",
                                "asset_identifier": "*.acme.com",
                                "eligible_for_bounty": True,
                                "max_severity_rating": "critical",
                            }
                        },
                    ]
                }
            }
        })

        with patch("lib_webbh.platform_api.hackerone.httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value.__aenter__.return_value
            instance.get = AsyncMock(return_value=mock_resp)

            client = HackerOneClient(api_token="tok", api_username="user")
            entries = await client.import_scope("acme")

            assert len(entries) == 1
            assert entries[0].asset_value == "*.acme.com"
            assert entries[0].eligible_for_bounty is True

    async def test_submit_report(self):
        from lib_webbh.platform_api.hackerone import HackerOneClient

        mock_resp = _mock_httpx_response({
            "data": {
                "id": "12345",
                "attributes": {"state": "new"},
            }
        }, status_code=201)

        with patch("lib_webbh.platform_api.hackerone.httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value.__aenter__.return_value
            instance.post = AsyncMock(return_value=mock_resp)

            client = HackerOneClient(api_token="tok", api_username="user")
            result = await client.submit_report("acme", "XSS", "body", "high")

            assert result.external_id == "12345"
            assert result.status == "new"

    async def test_sync_status(self):
        from lib_webbh.platform_api.hackerone import HackerOneClient

        mock_resp = _mock_httpx_response({
            "data": {"attributes": {"state": "triaged"}}
        })

        with patch("lib_webbh.platform_api.hackerone.httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value.__aenter__.return_value
            instance.get = AsyncMock(return_value=mock_resp)

            client = HackerOneClient(api_token="tok", api_username="user")
            status = await client.sync_status("12345")
            assert status == "triaged"


# ---------------------------------------------------------------------------
# Bugcrowd
# ---------------------------------------------------------------------------

class TestBugcrowdClient:
    async def test_import_scope(self):
        from lib_webbh.platform_api.bugcrowd import BugcrowdClient

        mock_resp = _mock_httpx_response({
            "data": {
                "relationships": {
                    "target_groups": {
                        "data": [
                            {
                                "relationships": {
                                    "targets": {
                                        "data": [
                                            {
                                                "attributes": {
                                                    "name": "api.acme.com",
                                                    "category": "website",
                                                    "uri": "https://api.acme.com",
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        })

        with patch("lib_webbh.platform_api.bugcrowd.httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value.__aenter__.return_value
            instance.get = AsyncMock(return_value=mock_resp)

            client = BugcrowdClient(api_token="tok")
            entries = await client.import_scope("acme-program")

            assert len(entries) == 1
            assert entries[0].asset_value == "api.acme.com"

    async def test_submit_report(self):
        from lib_webbh.platform_api.bugcrowd import BugcrowdClient

        mock_resp = _mock_httpx_response({
            "data": {"id": "sub-999", "attributes": {"state": "new"}}
        }, status_code=201)

        with patch("lib_webbh.platform_api.bugcrowd.httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value.__aenter__.return_value
            instance.post = AsyncMock(return_value=mock_resp)

            client = BugcrowdClient(api_token="tok")
            result = await client.submit_report("acme-prog", "SQLi", "body", "critical")

            assert result.external_id == "sub-999"


# ---------------------------------------------------------------------------
# Intigriti
# ---------------------------------------------------------------------------

class TestIntigritiClient:
    async def test_import_scope(self):
        from lib_webbh.platform_api.intigriti import IntigritiClient

        mock_resp = _mock_httpx_response({
            "domains": [
                {
                    "endpoint": "*.acme.com",
                    "type": "url",
                    "bountyEligible": True,
                    "severity": {"value": 4},
                }
            ]
        })

        with patch("lib_webbh.platform_api.intigriti.httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value.__aenter__.return_value
            instance.get = AsyncMock(return_value=mock_resp)

            client = IntigritiClient(api_token="tok")
            entries = await client.import_scope("acme")

            assert len(entries) == 1
            assert entries[0].asset_value == "*.acme.com"

    async def test_submit_report(self):
        from lib_webbh.platform_api.intigriti import IntigritiClient

        mock_resp = _mock_httpx_response({
            "submissionId": "INT-abc",
            "status": "created",
        }, status_code=201)

        with patch("lib_webbh.platform_api.intigriti.httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value.__aenter__.return_value
            instance.post = AsyncMock(return_value=mock_resp)

            client = IntigritiClient(api_token="tok")
            result = await client.submit_report("acme", "XSS", "body", "high")
            assert result.external_id == "INT-abc"


# ---------------------------------------------------------------------------
# YesWeHack
# ---------------------------------------------------------------------------

class TestYesWeHackClient:
    async def test_import_scope(self):
        from lib_webbh.platform_api.yeswehack import YesWeHackClient

        mock_resp = _mock_httpx_response({
            "scopes": [
                {
                    "scope": "acme.com",
                    "scope_type": "web-application",
                    "out_of_scope": False,
                }
            ]
        })

        with patch("lib_webbh.platform_api.yeswehack.httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value.__aenter__.return_value
            instance.get = AsyncMock(return_value=mock_resp)

            client = YesWeHackClient(api_token="tok")
            entries = await client.import_scope("acme")

            assert len(entries) == 1
            assert entries[0].asset_value == "acme.com"

    async def test_submit_report(self):
        from lib_webbh.platform_api.yeswehack import YesWeHackClient

        mock_resp = _mock_httpx_response({
            "id": 7777,
            "status": {"workflow_state": "new"},
        }, status_code=201)

        with patch("lib_webbh.platform_api.yeswehack.httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value.__aenter__.return_value
            instance.post = AsyncMock(return_value=mock_resp)

            client = YesWeHackClient(api_token="tok")
            result = await client.submit_report("acme", "SSRF", "body", "high")
            assert result.external_id == "7777"


# ---------------------------------------------------------------------------
# DB model extension
# ---------------------------------------------------------------------------

class TestBountySubmissionExtension:
    def test_has_external_id_column(self):
        from lib_webbh.database import BountySubmission
        cols = {c.name for c in BountySubmission.__table__.columns}
        assert "external_id" in cols

    def test_has_platform_response_column(self):
        from lib_webbh.database import BountySubmission
        cols = {c.name for c in BountySubmission.__table__.columns}
        assert "platform_response" in cols
