"""Playwright BrowserManager singleton for client-side testing."""

from __future__ import annotations

from playwright.async_api import async_playwright


class BrowserManager:
    """Singleton that manages a persistent Playwright Chromium browser instance."""

    _instance: BrowserManager | None = None
    _browser = None
    _contexts: dict[int, object] = {}

    def __new__(cls) -> BrowserManager:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    async def get_instance(cls) -> BrowserManager:
        """Return the singleton BrowserManager instance."""
        if cls._instance is None:
            cls._instance = cls()
            await cls._instance.initialize()
        return cls._instance

    async def initialize(self) -> None:
        """Launch a persistent chromium browser in headless mode."""
        pw = await async_playwright().start()
        self._browser = await pw.chromium.launch(headless=True)

    async def create_context(self, target_id: int):
        """Create an isolated browser context with a unique user data dir."""
        if self._browser is None:
            await self.initialize()

        context = await self._browser.new_context(
            storage_state=None,
            user_data_dir=f"/tmp/webbh_browser_{target_id}",
        )
        self._contexts[target_id] = context
        return context

    async def close_context(self, target_id: int) -> None:
        """Close a specific browser context."""
        context = self._contexts.pop(target_id, None)
        if context is not None:
            await context.close()

    async def cleanup(self) -> None:
        """Close all contexts and the browser."""
        for ctx in list(self._contexts.values()):
            try:
                await ctx.close()
            except Exception:
                pass
        self._contexts.clear()

        if self._browser is not None:
            await self._browser.close()
            self._browser = None
