"""Callback server entry point.

Starts:
  - Polling/management REST API on port 9091
  - HTTP interaction listener on port 9090
  - DNS interaction listener on port 9053 (UDP)
  - TCP interaction listener on port 9443
"""

import asyncio
import os

from aiohttp import web

from workers.callback.callback_store import CallbackStore
from workers.callback.api import create_app
from workers.callback.listeners import (
    start_http_listener,
    start_dns_listener,
    start_tcp_listener,
)

API_PORT = int(os.environ.get("CALLBACK_API_PORT", "9091"))


async def start_api(store: CallbackStore) -> web.AppRunner:
    """Start the callback management/polling REST API."""
    app = create_app(store=store)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", API_PORT)
    await site.start()
    return runner


async def main() -> None:
    store = CallbackStore()

    # Start all services sharing the same store.
    api_runner = await start_api(store)
    print(f"Callback API listening on :{API_PORT}", flush=True)

    http_runner = await start_http_listener(store)
    print(f"HTTP listener on :{os.environ.get('CALLBACK_HTTP_PORT', '9090')}", flush=True)

    dns_transport = await start_dns_listener(store)
    print(f"DNS listener on :{os.environ.get('CALLBACK_DNS_PORT', '9053')}/udp", flush=True)

    tcp_server = await start_tcp_listener(store)
    print(f"TCP listener on :{os.environ.get('CALLBACK_TCP_PORT', '9443')}", flush=True)

    try:
        # Run forever.
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        tcp_server.close()
        await tcp_server.wait_closed()
        dns_transport.close()
        await http_runner.cleanup()
        await api_runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
