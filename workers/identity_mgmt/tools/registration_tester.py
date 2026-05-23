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


# ── Block 1: Endpoint Discovery & Protocol Check ─────────────────────────────

reg_endpoints = []
try:
    reg_paths = [
        "/register", "/signup", "/api/register", "/api/signup",
        "/auth/register", "/auth/signup", "/api/v1/register", "/api/v1/signup",
        "/user/register", "/user/signup", "/api/user/register",
        "/account/create", "/api/account/create", "/join",
    ]
    client = make_client()
    for path in reg_paths:
        try:
            url = base_url.rstrip("/") + path
            resp = safe_request("GET", url, client)
            if resp is None or resp.status_code != 200:
                continue
            reg_endpoints.append(path)

            # Protocol enforcement
            if base_url.startswith("https://"):
                http_url = "http://" + base_url.split("://", 1)[1].rstrip("/") + path
                try:
                    with httpx.Client(follow_redirects=False, timeout=5, verify=False) as nr_c:
                        nr_resp = nr_c.get(http_url)
                        if nr_resp.status_code not in (301, 302, 307, 308):
                            results.append({{
                                "title": "Registration endpoint does not enforce HTTPS",
                                "description": f"{{path}} served over HTTP without redirect (status {{nr_resp.status_code}})",
                                "severity": "medium",
                                "data": {{"endpoint": path, "http_status": nr_resp.status_code}},
                            }})
                except Exception:
                    pass

            # CSRF token check
            csrf_patterns = [r"_token", r"csrf", r"__RequestVerificationToken", r"authenticity_token"]
            if not any(re.search(p, resp.text, re.IGNORECASE) for p in csrf_patterns):
                results.append({{
                    "title": "Registration form missing CSRF token",
                    "description": f"No CSRF token pattern detected on {{path}}",
                    "severity": "medium",
                    "data": {{"endpoint": path}},
                }})
        except Exception:
            pass
    client.close()
except Exception as e:
    results.append({{
        "title": "Endpoint discovery error",
        "description": str(e),
        "severity": "info",
        "data": {{"error": str(e)}},
    }})

# ── Block 2: Privilege Escalation via Registration Parameters ────────────────

try:
    uid = random.randint(10000, 99999)
    priv_payloads = [
        {{"role": "admin", "username": f"priv_role_{{uid}}", "email": f"priv_role_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
        {{"is_admin": True, "username": f"priv_isadmin_{{uid}}", "email": f"priv_isadmin_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
        {{"account_type": "admin", "username": f"priv_acct_{{uid}}", "email": f"priv_acct_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
        {{"user_type": "administrator", "username": f"priv_utype_{{uid}}", "email": f"priv_utype_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
        {{"admin": 1, "username": f"priv_admin1_{{uid}}", "email": f"priv_admin1_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
        {{"permissions": ["admin"], "username": f"priv_perm_{{uid}}", "email": f"priv_perm_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
    ]
    inj_keys = ["role", "is_admin", "account_type", "user_type", "admin", "permissions"]

    for ep in reg_endpoints:
        url = base_url.rstrip("/") + ep
        for payload, inj_key in zip(priv_payloads, inj_keys):
            try:
                c = make_client()
                resp = safe_request("POST", url, c, json=payload)
                c.close()
                if resp is None:
                    continue
                if resp.status_code in (200, 201):
                    results.append({{
                        "title": "Privilege escalation parameter accepted at registration",
                        "description": f"POST to {{ep}} with {{inj_key}}=<elevated> returned {{resp.status_code}}",
                        "severity": "high",
                        "data": {{"endpoint": ep, "injected_field": inj_key, "response_status": resp.status_code}},
                    }})
                else:
                    try:
                        body = resp.json()
                        if isinstance(body, dict) and body.get(inj_key) == payload[inj_key]:
                            results.append({{
                                "title": "Registration response reflects elevated role parameter",
                                "description": f"Response JSON contains {{inj_key}} with elevated value after POST to {{ep}}",
                                "severity": "high",
                                "data": {{"endpoint": ep, "injected_field": inj_key, "reflected_value": str(payload[inj_key])}},
                            }})
                    except Exception:
                        pass
            except Exception:
                pass
except Exception as e:
    results.append({{
        "title": "Privilege escalation test error",
        "description": str(e),
        "severity": "info",
        "data": {{"error": str(e)}},
    }})

# ── Block 3: Password Policy Enforcement ─────────────────────────────────────

try:
    uid = random.randint(10000, 99999)
    base_username = f"pwpolicy_{{uid}}"
    weak_passwords = [
        ("password", "dictionary word"),
        ("123456", "sequential numeric"),
        ("abc", "too short"),
        ("1", "single character"),
        ("", "empty string"),
        (base_username, "same as username"),
    ]
    for ep in reg_endpoints:
        url = base_url.rstrip("/") + ep
        for i, (weak_pwd, weakness) in enumerate(weak_passwords):
            try:
                c = make_client()
                resp = safe_request("POST", url, c, json={{
                    "username": f"{{base_username}}_{{i}}",
                    "email": f"pwpolicy_{{uid}}_{{i}}@example.com",
                    "password": weak_pwd,
                }})
                c.close()
                if resp is not None and resp.status_code in (200, 201):
                    results.append({{
                        "title": "Weak password accepted at registration",
                        "description": f"{{ep}} accepted password type '{{weakness}}' (status {{resp.status_code}})",
                        "severity": "high",
                        "data": {{"endpoint": ep, "weakness": weakness, "response_status": resp.status_code}},
                    }})
            except Exception:
                pass
except Exception as e:
    results.append({{
        "title": "Password policy test error",
        "description": str(e),
        "severity": "info",
        "data": {{"error": str(e)}},
    }})

# ── Block 4: Duplicate Account & Enumeration ─────────────────────────────────

try:
    uid = random.randint(10000, 99999)
    dup_email = f"dup_{{uid}}@example.com"
    dup_username = f"dupuser_{{uid}}"
    reveal_patterns = re.compile(
        r"(already|exist|taken|registered|in use|duplicate)", re.IGNORECASE
    )
    t_dup = None

    for ep in reg_endpoints:
        url = base_url.rstrip("/") + ep

        # Duplicate email
        try:
            c1 = make_client()
            safe_request("POST", url, c1, json={{
                "username": f"{{dup_username}}_a", "email": dup_email, "password": "T3stP@ssw0rd!",
            }})
            c1.close()
            c2 = make_client()
            t_start = time.monotonic()
            resp2 = safe_request("POST", url, c2, json={{
                "username": f"{{dup_username}}_b", "email": dup_email, "password": "T3stP@ssw0rd!",
            }})
            t_dup = time.monotonic() - t_start
            c2.close()
            if resp2 is not None:
                if resp2.status_code in (200, 201):
                    results.append({{
                        "title": "Duplicate email registration accepted",
                        "description": f"{{ep}} accepted second registration with same email (status {{resp2.status_code}})",
                        "severity": "high",
                        "data": {{"endpoint": ep, "duplicate_email": True, "response_status": resp2.status_code}},
                    }})
                elif reveal_patterns.search(resp2.text) and "email" in resp2.text.lower():
                    results.append({{
                        "title": "Email enumeration via registration rejection message",
                        "description": f"{{ep}} rejection message reveals whether email is registered",
                        "severity": "medium",
                        "data": {{"endpoint": ep, "message_reveals_email": True}},
                    }})
        except Exception:
            pass

        # Duplicate username
        try:
            c3 = make_client()
            safe_request("POST", url, c3, json={{
                "username": dup_username, "email": f"novel_a_{{uid}}@example.com", "password": "T3stP@ssw0rd!",
            }})
            c3.close()
            c4 = make_client()
            resp4 = safe_request("POST", url, c4, json={{
                "username": dup_username, "email": f"novel_b_{{uid}}@example.com", "password": "T3stP@ssw0rd!",
            }})
            c4.close()
            if resp4 is not None:
                if resp4.status_code in (200, 201):
                    results.append({{
                        "title": "Duplicate username registration accepted",
                        "description": f"{{ep}} accepted second registration with same username (status {{resp4.status_code}})",
                        "severity": "high",
                        "data": {{"endpoint": ep, "duplicate_username": True, "response_status": resp4.status_code}},
                    }})
                elif reveal_patterns.search(resp4.text) and "username" in resp4.text.lower():
                    results.append({{
                        "title": "Username enumeration via registration rejection message",
                        "description": f"{{ep}} rejection message reveals whether username is taken",
                        "severity": "medium",
                        "data": {{"endpoint": ep, "message_reveals_username": True}},
                    }})
        except Exception:
            pass

        # Timing-based enumeration
        try:
            if t_dup is not None:
                c5 = make_client()
                t_novel_start = time.monotonic()
                safe_request("POST", url, c5, json={{
                    "username": f"novel_timing_{{uid}}", "email": f"novel_timing_{{uid}}@example.com", "password": "T3stP@ssw0rd!",
                }})
                t_novel = time.monotonic() - t_novel_start
                c5.close()
                if abs(t_dup - t_novel) > 0.5:
                    results.append({{
                        "title": "Possible timing-based user enumeration at registration",
                        "description": f"{{ep}} timing delta {{abs(t_dup - t_novel):.2f}}s between duplicate and novel registration",
                        "severity": "low",
                        "data": {{"endpoint": ep, "t_dup": round(t_dup, 3), "t_novel": round(t_novel, 3)}},
                    }})
        except Exception:
            pass

except Exception as e:
    results.append({{
        "title": "Duplicate account test error",
        "description": str(e),
        "severity": "info",
        "data": {{"error": str(e)}},
    }})

print(json.dumps(results))
'''
        return ["python3", "-c", script]

    def parse_output(self, stdout):
        import json
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
