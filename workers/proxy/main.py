"""Traffic proxy entry point.

Starts:
  - mitmproxy reverse proxy on port 8080
  - Rule Manager REST API on port 8081
"""

import asyncio
import os
import subprocess
import sys

from aiohttp import web

from workers.proxy.rule_store import RuleStore
from workers.proxy.rule_manager import create_app

PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))
API_PORT = int(os.environ.get("PROXY_API_PORT", "8081"))
UPSTREAM_MODE = os.environ.get("PROXY_UPSTREAM_MODE", "regular")


async def start_api(store: RuleStore) -> web.AppRunner:
    """Start the rule manager REST API."""
    app = create_app(store=store)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", API_PORT)
    await site.start()
    return runner


def start_mitmproxy(store: RuleStore) -> subprocess.Popen:
    """Launch mitmproxy in a subprocess with our addon.

    We write a small bootstrap script that creates the addon with the
    shared RuleStore instance. For the Docker container, mitmproxy runs
    as a child process while the API server runs in the main asyncio loop.
    """
    addon_script = os.path.join(os.path.dirname(__file__), "_mitm_bootstrap.py")

    # Write a bootstrap script that mitmproxy can load as a script addon.
    # The addon communicates with the rule API over localhost.
    with open(addon_script, "w") as f:
        f.write(
            f"""\
import json, urllib.request
from mitmproxy import http

_API = "http://127.0.0.1:{API_PORT}"


def _get_rules(url: str) -> list:
    try:
        req = urllib.request.Request(f"{{_API}}/rules")
        with urllib.request.urlopen(req, timeout=1) as resp:
            rules = json.loads(resp.read())
    except Exception:
        return []
    import fnmatch
    return [r for r in rules if fnmatch.fnmatch(url, r.get("match", {{}}).get("url_pattern", "*"))]


def request(flow: http.HTTPFlow) -> None:
    rules = _get_rules(flow.request.pretty_url)
    for rule in rules:
        action = rule.get("action", {{}})
        atype = action.get("type")
        if atype == "replace_param":
            name, value = action.get("name", ""), action.get("value", "")
            if flow.request.method in ("GET", "HEAD", "OPTIONS"):
                flow.request.query[name] = value
            elif flow.request.urlencoded_form:
                flow.request.urlencoded_form[name] = value
        elif atype == "strip_header":
            name = action.get("name", "")
            if name in flow.request.headers:
                del flow.request.headers[name]
        elif atype == "inject_header":
            flow.request.headers[action.get("name", "")] = action.get("value", "")
        elif atype == "replace_body":
            flow.request.text = action.get("content", "")
        elif atype == "strip_cookie":
            name = action.get("name", "")
            if name in flow.request.cookies:
                del flow.request.cookies[name]


def response(flow: http.HTTPFlow) -> None:
    rules = _get_rules(flow.request.pretty_url)
    for rule in rules:
        action = rule.get("action", {{}})
        atype = action.get("type")
        if atype == "inject_response_header":
            flow.response.headers[action.get("name", "")] = action.get("value", "")
        elif atype == "strip_response_header":
            name = action.get("name", "")
            if name in flow.response.headers:
                del flow.response.headers[name]
"""
        )

    cmd = [
        sys.executable, "-m", "mitmproxy.tools.main",
        "--mode", UPSTREAM_MODE,
        "--listen-port", str(PROXY_PORT),
        "--set", "block_global=false",
        "--scripts", addon_script,
        "--quiet",
    ]
    return subprocess.Popen(cmd)


async def main() -> None:
    store = RuleStore()

    # Start the REST API first so the mitmproxy addon can query it.
    runner = await start_api(store)
    print(f"Rule Manager API listening on :{API_PORT}", flush=True)

    # Start mitmproxy as a subprocess.
    mitm = start_mitmproxy(store)
    print(f"mitmproxy listening on :{PROXY_PORT}", flush=True)

    try:
        # Keep running until mitmproxy exits or we get interrupted.
        while mitm.poll() is None:
            await asyncio.sleep(2)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        mitm.terminate()
        mitm.wait(timeout=5)
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
