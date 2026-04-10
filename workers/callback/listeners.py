"""OOB interaction listeners — HTTP, DNS, TCP.

Each listener captures incoming connections and records them as
interactions in the shared CallbackStore.
"""

import asyncio
import json
import os
import struct
from datetime import datetime, timezone

from aiohttp import web

from workers.callback.callback_store import CallbackStore

HTTP_PORT = int(os.environ.get("CALLBACK_HTTP_PORT", "9090"))
DNS_PORT = int(os.environ.get("CALLBACK_DNS_PORT", "9053"))
TCP_PORT = int(os.environ.get("CALLBACK_TCP_PORT", "9443"))
CALLBACK_DOMAIN = os.environ.get("CALLBACK_DOMAIN", "cb.internal")


# ---------------------------------------------------------------------------
# HTTP Listener (port 9090)
# ---------------------------------------------------------------------------

def create_http_app(store: CallbackStore) -> web.Application:
    """HTTP listener that captures requests to /cb/{callback_id}."""

    async def handle_callback(request: web.Request) -> web.Response:
        cb_id = request.match_info["cb_id"]
        cb = store.get(cb_id)
        if cb is None:
            return web.Response(status=404, text="not found")

        body = await request.text()
        interaction = {
            "protocol": "http",
            "method": request.method,
            "path": str(request.rel_url),
            "headers": dict(request.headers),
            "body": body[:4096],
            "source_ip": request.remote,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        store.record_interaction(cb_id, interaction)
        return web.Response(status=200, text="ok")

    app = web.Application()
    # Capture any method to /cb/{cb_id} and any sub-paths.
    app.router.add_route("*", "/cb/{cb_id}", handle_callback)
    app.router.add_route("*", "/cb/{cb_id}/{path:.*}", handle_callback)
    return app


async def start_http_listener(store: CallbackStore) -> web.AppRunner:
    app = create_http_app(store)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    return runner


# ---------------------------------------------------------------------------
# DNS Listener (port 9053/udp)
# ---------------------------------------------------------------------------

class DnsProtocol(asyncio.DatagramProtocol):
    """Minimal DNS responder that records queries for {cb_id}.cb.internal."""

    def __init__(self, store: CallbackStore):
        self.store = store
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        try:
            qname = self._extract_qname(data)
        except Exception:
            return

        # Extract callback_id: expects {callback_id}.cb.internal
        suffix = f".{CALLBACK_DOMAIN}"
        if qname.endswith(suffix):
            cb_id = qname[: -len(suffix)]
        elif qname.endswith(suffix + "."):
            cb_id = qname[: -len(suffix) - 1]
        else:
            # Not our domain — send NXDOMAIN.
            self._send_nxdomain(data, addr)
            return

        cb = self.store.get(cb_id)
        if cb is not None:
            self.store.record_interaction(
                cb_id,
                {
                    "protocol": "dns",
                    "qname": qname,
                    "source_ip": addr[0],
                    "source_port": addr[1],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )

        # Reply with 127.0.0.1 A record so the lookup succeeds.
        self._send_a_reply(data, addr)

    @staticmethod
    def _extract_qname(data: bytes) -> str:
        """Parse the QNAME from a raw DNS query packet."""
        # Skip the 12-byte header.
        offset = 12
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                break
            offset += 1
            labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
            offset += length
        return ".".join(labels).lower()

    def _send_a_reply(self, query: bytes, addr: tuple) -> None:
        """Build a minimal DNS A-record response pointing to 127.0.0.1."""
        if len(query) < 12:
            return
        txid = query[:2]
        flags = b"\x81\x80"  # QR=1, AA=1, RCODE=0
        counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"  # 1 question, 1 answer
        # Copy the question section.
        qsection_end = 12
        while qsection_end < len(query) and query[qsection_end] != 0:
            qsection_end += query[qsection_end] + 1
        qsection_end += 5  # null byte + QTYPE(2) + QCLASS(2)
        question = query[12:qsection_end]
        # Answer: pointer to name (0xc00c), type A, class IN, TTL 60, RDLENGTH 4, 127.0.0.1
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
        reply = txid + flags + counts + question + answer
        self.transport.sendto(reply, addr)

    def _send_nxdomain(self, query: bytes, addr: tuple) -> None:
        if len(query) < 12:
            return
        txid = query[:2]
        flags = b"\x81\x83"  # QR=1, AA=1, RCODE=3 (NXDOMAIN)
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        qsection_end = 12
        while qsection_end < len(query) and query[qsection_end] != 0:
            qsection_end += query[qsection_end] + 1
        qsection_end += 5
        question = query[12:qsection_end]
        reply = txid + flags + counts + question
        self.transport.sendto(reply, addr)


async def start_dns_listener(store: CallbackStore) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DnsProtocol(store),
        local_addr=("0.0.0.0", DNS_PORT),
    )
    return transport


# ---------------------------------------------------------------------------
# TCP Listener (port 9443)
# ---------------------------------------------------------------------------

class TcpHandler(asyncio.Protocol):
    """Raw TCP connection recorder.

    Expects the first line sent by the client to contain the callback_id.
    Records the connection and any data received.
    """

    def __init__(self, store: CallbackStore):
        self.store = store
        self.transport = None
        self.peer = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")

    def data_received(self, data: bytes) -> None:
        self.buffer += data
        # Try to extract callback_id from first line.
        if b"\n" in self.buffer or len(self.buffer) > 256:
            first_line = self.buffer.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
            cb_id = first_line

            cb = self.store.get(cb_id)
            if cb is not None:
                self.store.record_interaction(
                    cb_id,
                    {
                        "protocol": "tcp",
                        "source_ip": self.peer[0] if self.peer else "unknown",
                        "source_port": self.peer[1] if self.peer else 0,
                        "data": self.buffer[:4096].decode("utf-8", errors="replace"),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                )

            self.transport.write(b"ok\n")
            self.transport.close()

    def connection_lost(self, exc) -> None:
        pass


async def start_tcp_listener(store: CallbackStore) -> asyncio.Server:
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: TcpHandler(store),
        "0.0.0.0",
        TCP_PORT,
    )
    return server
