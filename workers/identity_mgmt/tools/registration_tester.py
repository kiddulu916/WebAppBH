"""Registration process testing tool (WSTG-IDNT-02)."""

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.concurrency import WeightClass


class RegistrationTester(IdentityMgmtTool):
    """Test user registration processes (WSTG-IDNT-02)."""

    name = "registration_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, "target_value", str(target))
        base_url = (
            target_url
            if target_url.startswith(("http://", "https://"))
            else f"https://{target_url}"
        )

        script = f'''
import httpx
import json
import random
import re
import time

results = []
base_url = "{base_url}"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]
_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.7", "de-DE,de;q=0.9,en;q=0.7",
]
_REFERERS = [
    "https://www.google.com/search?q=signup",
    "https://www.bing.com/search?q=register",
    "https://duckduckgo.com/?q=create+account",
]


def _rand_xff():
    pools = [
        (68, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),
        (76, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),
        (172, 58, random.randint(0, 255), random.randint(1, 254)),
        (108, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),
    ]
    octets = random.choice(pools)
    return ".".join(str(o) for o in octets)


def make_client():
    return httpx.Client(
        follow_redirects=True,
        timeout=10,
        verify=False,
        headers={{
            "User-Agent": random.choice(USER_AGENTS),
            "X-Forwarded-For": _rand_xff(),
            "Accept-Language": random.choice(_ACCEPT_LANGUAGES),
            "Referer": random.choice(_REFERERS),
        }},
    )


def safe_request(method, url, client, max_retries=3, **kwargs):
    time.sleep(random.uniform(0.3, 1.5))
    delay = 2
    for attempt in range(max_retries):
        try:
            resp = client.request(method, url, **kwargs)
            if resp.status_code in (429, 503):
                time.sleep(delay)
                delay = min(delay * 2, 8)
                continue
            return resp
        except Exception:
            return None
    return None


print(json.dumps(results))
'''
        return ["python3", "-c", script]

    def parse_output(self, stdout):
        import json
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
