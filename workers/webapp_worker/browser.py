"""Semaphore-gated Playwright Chromium browser manager.

Manages a single headless Chromium instance shared across browser-based
analysis stages.  Tabs are gated by an asyncio.Semaphore so concurrent
stages never exceed MAX_TABS open pages.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from lib_webbh import setup_logger

log = setup_logger("browser-manager")


class BrowserManager:
    """Lifecycle wrapper around a single Playwright Chromium browser."""

    def __init__(
        self,
        max_tabs: int | None = None,
        page_timeout: int | None = None,
    ) -> None:
        if max_tabs is None:
            max_tabs = int(os.environ.get("MAX_TABS", "3"))
        if page_timeout is None:
            page_timeout = int(os.environ.get("PAGE_TIMEOUT", "30"))

        self._max_tabs = max_tabs
        self._page_timeout_ms = page_timeout * 1000
        self._sem = asyncio.Semaphore(max_tabs)

        # Set after start()
        self._playwright: Any = None
        self._browser: Any = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Launch a headless Chromium browser.

        Playwright is lazy-imported so that unit tests never need the
        real package installed.
        """
        from playwright.async_api import async_playwright  # lazy import

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
            ],
        )
        log.info(
            f"Chromium launched (max_tabs={self._max_tabs}, timeout={self._page_timeout_ms}ms)",
        )

    async def shutdown(self) -> None:
        """Close browser and Playwright."""
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                log.exception("Error closing browser")
            self._browser = None

        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:
                log.exception("Error stopping Playwright")
            self._playwright = None

        log.info("Browser manager shut down")

    # ------------------------------------------------------------------
    # Tab management
    # ------------------------------------------------------------------

    async def new_page(self, headers: dict[str, str] | None = None) -> Any:
        """Open a new browser tab, gated by the semaphore.

        Parameters
        ----------
        headers:
            Optional extra HTTP headers injected into every request made
            by this page.

        Returns
        -------
        playwright.async_api.Page
        """
        await self._sem.acquire()
        try:
            page = await self._browser.new_page()
            page.set_default_timeout(self._page_timeout_ms)
            if headers:
                await page.set_extra_http_headers(headers)
            log.debug(f"New page opened (available tabs: {self._sem._value})")
            return page
        except Exception:
            self._sem.release()
            raise

    async def release_page(self, page: Any) -> None:
        """Close *page* and release its semaphore slot."""
        try:
            await page.close()
        except Exception:
            log.exception("Error closing page")
        finally:
            self._sem.release()
            log.debug(f"Page released (available tabs: {self._sem._value})")
