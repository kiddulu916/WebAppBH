# tests/_stage2_helpers.py
"""Shared aiohttp-session mock helpers for Stage 2 probe tests.

Several probes (Banner, ErrorPage, WAF) instantiate ``aiohttp.ClientSession``
and consume the response via ``async with``. Patching that path requires a
mock that supports ``__aenter__``/``__aexit__`` on both the session and the
response context. These helpers normalize that boilerplate so individual
test files don't drift.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock


class FakeHeaders(dict[str, str]):
    """Dict subclass mimicking aiohttp's CIMultiDictProxy.

    Supports ``dict()`` enumeration, ``.get()``, and ``.getall("Set-Cookie", default)``.
    """

    def __init__(self, headers: dict[str, str], cookies: list[str] | None = None) -> None:
        super().__init__(headers)
        self._cookies = cookies or []

    def getall(self, name: str, default):
        if name == "Set-Cookie":
            return self._cookies
        return default


def fake_session(
    *,
    headers: dict[str, str] | None = None,
    status: int = 200,
    body: str | None = None,
    cookies: list[str] | None = None,
    exception: Exception | None = None,
) -> AsyncMock:
    """Build a ``ClientSession`` mock that supports the ``async with session.get(...)`` pattern.

    Pass ``exception`` to make ``session.get()`` raise; otherwise the mocked
    response carries the given status / headers / cookies. ``body`` is awaited
    via ``resp.text()``.
    """
    resp = AsyncMock()
    resp.status = status
    resp.headers = FakeHeaders(headers or {}, cookies)
    if body is not None:
        resp.text = AsyncMock(return_value=body)

    resp_ctx = AsyncMock()
    resp_ctx.__aenter__ = AsyncMock(return_value=resp)
    resp_ctx.__aexit__ = AsyncMock(return_value=False)

    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    if exception is not None:
        session.get = MagicMock(side_effect=exception)
    else:
        session.get = MagicMock(return_value=resp_ctx)
    return session
