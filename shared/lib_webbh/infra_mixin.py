"""Infrastructure mixin providing proxy, callback, credential, and safety helpers.

Worker base_tool classes inherit from this mixin to get access to
shared infrastructure services and the safety policy methods required
by the design doc (restructure-02-safety-policy).
"""

import json
import logging
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

    # -- Safety policy helpers --

    # Class-level blocklist shared across all instances to prevent
    # accidentally targeting real users discovered during a scan.
    _REAL_USER_BLOCKLIST: set[str] = set()

    async def log_discovered_user(
        self,
        target_id: int,
        username: str | None = None,
        email: str | None = None,
        source: str | None = None,
    ) -> None:
        """Record a discovered real user without taking any action.

        Adds the identifiers to the blocklist so validate_target_user()
        will reject them, and persists an Observation for audit purposes.
        """
        from lib_webbh.database import Observation, get_session

        if username:
            self._REAL_USER_BLOCKLIST.add(username)
        if email:
            self._REAL_USER_BLOCKLIST.add(email)

        async with get_session() as session:
            obs = Observation(
                target_id=target_id,
                observation_type="discovered_user",
                data={
                    "username": username,
                    "email": email,
                    "source": source,
                    "action_taken": "none — real user, documented only",
                },
            )
            session.add(obs)
            await session.commit()

    async def on_escalated_access(
        self,
        target_id: int,
        access_type: str,
        access_method: str,
        session_data: str,
        data_exposed: str,
        severity: str,
        worker_type: str = "unknown",
    ) -> None:
        """Document escalated access and halt further probing.

        Encrypts session data at rest using Fernet, creates a Vulnerability
        record and an EscalationContext record.  Should be called by any
        credential-dependent worker that discovers unintended elevated access.
        """
        from cryptography.fernet import Fernet
        from lib_webbh.database import EscalationContext, Vulnerability, get_session

        key = os.environ.get("FERNET_KEY", Fernet.generate_key().decode())
        f = Fernet(key.encode() if isinstance(key, str) else key)
        encrypted = f.encrypt(session_data.encode()).decode()

        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id,
                severity=severity,
                title=f"Escalated Access: {access_type}",
                worker_type=worker_type,
                vuln_type="escalated_access",
                confirmed=True,
            )
            session.add(vuln)
            await session.flush()

            esc = EscalationContext(
                target_id=target_id,
                vulnerability_id=vuln.id,
                access_type=access_type,
                access_method=access_method,
                session_data=encrypted,
                data_exposed=data_exposed,
                severity=severity,
            )
            session.add(esc)
            await session.commit()

        _log = logging.getLogger("infra_mixin")
        _log.warning(
            "Escalated access detected — halting further probing",
            extra={
                "target_id": target_id,
                "access_type": access_type,
                "severity": severity,
            },
        )
