"""OauthTesterTool -- Stage 2 OAuth flow vulnerability testing.

Pure-httpx tool that tests OAuth endpoints for:
- State parameter CSRF
- Redirect URI bypass variants
- Scope escalation
- PKCE downgrade attacks
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.concurrency import WeightClass

logger = setup_logger("oauth-tester")


class OauthTesterTool(ApiTestTool):
    """Test OAuth flows for common misconfigurations."""

    name = "oauth_tester"
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Redirect URI variant generation
    # ------------------------------------------------------------------

    def generate_redirect_uri_variants(self, callback_url: str) -> list[str]:
        """Generate redirect_uri bypass attempts from a legitimate callback URL.

        Returns a list of modified URLs that attempt to redirect to attacker.com.
        """
        parsed = urlparse(callback_url)
        variants: list[str] = []

        # 1. Replace domain with attacker.com
        replaced = parsed._replace(netloc="attacker.com")
        variants.append(urlunparse(replaced))

        # 2. Path traversal: append /../attacker.com
        traversal_path = parsed.path.rstrip("/") + "/../attacker.com"
        traversal = parsed._replace(path=traversal_path)
        variants.append(urlunparse(traversal))

        # 3. Scheme downgrade: http instead of https
        downgraded = parsed._replace(scheme="http")
        variants.append(urlunparse(downgraded))

        # 4. Subdomain trick: prepend attacker. to domain
        subdomain = parsed._replace(netloc=f"attacker.{parsed.netloc}")
        variants.append(urlunparse(subdomain))

        # 5. Open redirect chain: append ?next=https://attacker.com
        chain_path = parsed.path.rstrip("/") + "?next=https://attacker.com"
        chain = parsed._replace(path=chain_path)
        variants.append(urlunparse(chain))

        return variants

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping oauth_tester -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        oauth_urls = await self._get_oauth_urls(target_id)
        if not oauth_urls:
            log.info("No OAuth URLs found")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        client = httpx.AsyncClient(
            timeout=15.0,
            headers=headers or {},
            follow_redirects=False,  # We want to inspect redirects
        )

        try:
            for asset_id, url in oauth_urls:
                base_url = url if url.startswith("http") else f"https://{url}"

                # ---------------------------------------------------------
                # Test 1: State parameter CSRF
                # ---------------------------------------------------------
                try:
                    resp = await client.get(base_url)
                    if resp.status_code in (200, 302, 301):
                        location = resp.headers.get("location", "")
                        # Check if state param is missing from redirect
                        if resp.status_code in (301, 302) and "state=" not in location:
                            stats["found"] += 1
                            stats["in_scope"] += 1
                            stats["new"] += 1
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="medium",
                                title="OAuth missing state parameter (CSRF)",
                                description=(
                                    f"OAuth endpoint {base_url} redirects without "
                                    f"a state parameter, allowing CSRF attacks."
                                ),
                                poc=f"GET {base_url} -> {location}",
                            )
                except Exception as exc:
                    log.debug(f"State CSRF test failed for {base_url}: {exc}")

                # ---------------------------------------------------------
                # Test 2: Redirect URI bypass
                # ---------------------------------------------------------
                variants = self.generate_redirect_uri_variants(base_url)
                for variant in variants:
                    try:
                        resp = await client.get(
                            base_url,
                            params={"redirect_uri": variant},
                        )
                        # If server accepts an attacker-controlled redirect
                        if resp.status_code in (200, 302, 301):
                            location = resp.headers.get("location", "")
                            if "attacker.com" in location:
                                stats["found"] += 1
                                stats["in_scope"] += 1
                                stats["new"] += 1
                                await self._save_vulnerability(
                                    target_id=target_id,
                                    asset_id=asset_id,
                                    severity="high",
                                    title="OAuth redirect_uri bypass",
                                    description=(
                                        f"OAuth endpoint accepted attacker-controlled "
                                        f"redirect_uri: {variant}"
                                    ),
                                    poc=f"redirect_uri={variant} -> {location}",
                                )
                                break  # One bypass is enough per URL
                    except Exception as exc:
                        log.debug(f"Redirect URI test failed for {variant}: {exc}")

                # ---------------------------------------------------------
                # Test 3: Scope escalation
                # ---------------------------------------------------------
                try:
                    resp = await client.get(
                        base_url,
                        params={"scope": "admin openid profile email"},
                    )
                    if resp.status_code in (200, 302, 301):
                        location = resp.headers.get("location", "")
                        if "admin" in location.lower():
                            stats["found"] += 1
                            stats["in_scope"] += 1
                            stats["new"] += 1
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="high",
                                title="OAuth scope escalation",
                                description=(
                                    f"OAuth endpoint {base_url} accepted elevated "
                                    f"scope 'admin' without rejection."
                                ),
                                poc=f"scope=admin openid profile email",
                            )
                except Exception as exc:
                    log.debug(f"Scope escalation test failed for {base_url}: {exc}")

                # ---------------------------------------------------------
                # Test 4: PKCE downgrade
                # ---------------------------------------------------------
                try:
                    # Request auth code without code_challenge (PKCE)
                    resp = await client.get(
                        base_url,
                        params={
                            "response_type": "code",
                            "code_challenge_method": "",
                        },
                    )
                    if resp.status_code in (200, 302, 301):
                        location = resp.headers.get("location", "")
                        if "code=" in location:
                            stats["found"] += 1
                            stats["in_scope"] += 1
                            stats["new"] += 1
                            await self._save_vulnerability(
                                target_id=target_id,
                                asset_id=asset_id,
                                severity="medium",
                                title="OAuth PKCE downgrade",
                                description=(
                                    f"OAuth endpoint {base_url} issued auth code "
                                    f"without PKCE challenge, allowing code interception."
                                ),
                                poc=f"response_type=code without code_challenge",
                            )
                except Exception as exc:
                    log.debug(f"PKCE downgrade test failed for {base_url}: {exc}")

        finally:
            await client.aclose()

        await self.update_tool_state(target_id, container_name)
        log.info("oauth_tester complete", extra=stats)
        return stats
