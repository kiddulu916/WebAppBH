"""Infrastructure mixin providing proxy, callback, and credential helpers.

Worker base_tool classes inherit from this mixin to get access to
shared infrastructure services.
"""

import json
import os
from pathlib import Path
from typing import Optional


class InfrastructureMixin:
    """Mixin for worker base tools. Provides proxy, callback, credential access."""

    _proxy_url = os.environ.get("PROXY_URL", "http://proxy:8080")
    _callback_api = os.environ.get("CALLBACK_API", "http://callback:9091")

    # -- Proxy helpers --

    async def request_via_proxy(self, http_client, method, url, **kwargs):
        """Route a request through the traffic proxy."""
        kwargs.setdefault("proxy", self._proxy_url)
        return await http_client.request(method, url, **kwargs)

    async def request_direct(self, http_client, method, url, **kwargs):
        """Send a request directly, bypassing the proxy."""
        kwargs.pop("proxy", None)
        return await http_client.request(method, url, **kwargs)

    # -- Callback helpers --

    async def register_callback(self, http_client, protocols=None):
        """Register a new callback with the callback server."""
        resp = await http_client.post(
            f"{self._callback_api}/callbacks",
            json={"protocols": protocols or ["http"]},
        )
        data = await resp.json()
        return data["id"]

    async def check_callback(self, http_client, callback_id, timeout=30, poll_interval=2):
        """Poll the callback server for interactions."""
        import asyncio

        elapsed = 0
        while elapsed < timeout:
            resp = await http_client.get(f"{self._callback_api}/callbacks/{callback_id}")
            data = await resp.json()
            if data.get("interactions"):
                return data["interactions"]
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        return []

    async def cleanup_callback(self, http_client, callback_id):
        """Delete a callback registration."""
        await http_client.delete(f"{self._callback_api}/callbacks/{callback_id}")

    # -- Credential helpers --

    def _load_credentials(self, target_id: int) -> Optional[dict]:
        """Load credentials from config file."""
        creds_path = Path(f"shared/config/{target_id}/credentials.json")
        if creds_path.exists():
            return json.loads(creds_path.read_text())
        return None

    async def get_tester_session(self, target_id: int) -> Optional[dict]:
        """Get the Tester credentials for authenticated testing."""
        creds = self._load_credentials(target_id)
        if creds and "tester" in creds:
            return creds["tester"]
        return None

    def get_target_user(self, target_id: int) -> Optional[dict]:
        """Get the Testing User identifiers (no password)."""
        creds = self._load_credentials(target_id)
        if creds and "testing_user" in creds:
            user = creds["testing_user"]
            return {
                "username": user.get("username"),
                "email": user.get("email"),
                "profile_url": user.get("profile_url"),
            }
        return None

    def validate_target_user(self, target_id: int, identifier: str) -> bool:
        """Check if an identifier matches the Testing User."""
        user = self.get_target_user(target_id)
        if not user:
            return False
        return identifier in (user.get("username"), user.get("email"))
