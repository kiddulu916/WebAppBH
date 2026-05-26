"""Account provisioning testing tool (WSTG-IDNT-03)."""

from __future__ import annotations

import json

from lib_webbh import get_session, push_task

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.concurrency import WeightClass


class AccountProvisionTester(IdentityMgmtTool):
    """Test account provisioning/de-provisioning workflows (WSTG-IDNT-03)."""

    name = "account_provision_tester"
    weight_class = WeightClass.HEAVY

    async def execute(self, target, scope_manager, target_id, container_name, credentials=None):
        """Enrich credentials with testing_user before delegating to base execute."""
        testing_user = await self.get_testing_user_credentials(target_id)
        enriched = {"tester": credentials, "testing_user": testing_user}
        return await super().execute(
            target, scope_manager, target_id, container_name, credentials=enriched
        )

    def build_command(self, target, credentials=None):
        target_url = getattr(target, "target_value", str(target))
        base_url = (
            target_url
            if target_url.startswith(("http://", "https://"))
            else f"https://{target_url}"
        )

        credentials = credentials or {}
        tester = credentials.get("tester") or {}
        testing_user_creds = credentials.get("testing_user") or {}

        tester_username = tester.get("username", "")
        tester_password = tester.get("password", "")
        tester_auth_type = tester.get("auth_type", "form")
        tester_login_url = tester.get("login_url", "")
        testing_user_username = testing_user_creds.get("username", "")
        testing_user_email = testing_user_creds.get("email", "")
        testing_user_password = testing_user_creds.get("password", "")
        testing_user_auth_type = testing_user_creds.get("auth_type", "form")
        testing_user_login_url = testing_user_creds.get("login_url", "")

        tester_username_s = json.dumps(tester_username)
        tester_password_s = json.dumps(tester_password)
        tester_auth_type_s = json.dumps(tester_auth_type)
        tester_login_url_s = json.dumps(tester_login_url)
        testing_user_username_s = json.dumps(testing_user_username)
        testing_user_email_s = json.dumps(testing_user_email)
        testing_user_password_s = json.dumps(testing_user_password)
        testing_user_auth_type_s = json.dumps(testing_user_auth_type)
        testing_user_login_url_s = json.dumps(testing_user_login_url)

        script = f'''
import httpx
import json
import random
import re
import time

results = []
base_url = "{base_url}"

# ── Injected credentials ───────────────────────────────────────────────────────────────────────────────
tester_username = {tester_username_s}
tester_password = {tester_password_s}
tester_auth_type = {tester_auth_type_s}
tester_login_url = {tester_login_url_s}
testing_user_username = {testing_user_username_s}
testing_user_email = {testing_user_email_s}
testing_user_password = {testing_user_password_s}
testing_user_auth_type = {testing_user_auth_type_s}
testing_user_login_url = {testing_user_login_url_s}

# ── Shared helpers ────────────────────────────────────────────────────────────────────────────
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
_ACCEPT_LANGUAGES = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.7", "de-DE,de;q=0.9,en;q=0.7"]
_REFERERS = [
    "https://www.google.com/search?q=admin+panel",
    "https://www.bing.com/search?q=create+account",
    "https://duckduckgo.com/?q=user+provisioning",
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


# ── Acquire tester token ──────────────────────────────────────────────────────────────────────────────
tester_token = None
_tester_auth_header = {{}}
if tester_username and tester_password:
    if tester_auth_type == "basic":
        import base64 as _b64
        tester_token = _b64.b64encode(f"{{tester_username}}:{{tester_password}}".encode()).decode()
        _tester_auth_header = {{"Authorization": f"Basic {{tester_token}}"}}
    elif tester_auth_type in ("form", "bearer") and tester_login_url:
        try:
            _c = make_client()
            _login_payload = {{"username": tester_username, "password": tester_password}}
            _resp = _c.post(tester_login_url, json=_login_payload, timeout=10)
            if _resp.status_code in (200, 201):
                _data = {{}}
                try:
                    _data = _resp.json()
                except Exception:
                    pass
                tester_token = _data.get("token") or _data.get("access_token") or _data.get("auth_token")
                if not tester_token:
                    tester_token = _resp.cookies.get("session") or _resp.cookies.get("auth") or _resp.cookies.get("token")
            _c.close()
        except Exception:
            pass
        _tester_auth_header = {{"Authorization": f"Bearer {{tester_token}}"}} if tester_token else {{}}


# ── Block 1: Provisioning Endpoint Discovery ──────────────────────────────────────────────

found_provision_endpoints = []
try:
    provision_paths = [
        "/api/users", "/api/v1/users", "/api/accounts", "/api/v1/accounts",
        "/admin/users", "/api/admin/users", "/api/v1/admin/users",
        "/users/create", "/api/users/create", "/api/v1/provision", "/api/provision",
    ]
    for path in provision_paths:
        try:
            c = make_client()
            url = base_url.rstrip("/") + path
            resp = safe_request("GET", url, c)
            c.close()
            if resp is None:
                continue
            if resp.status_code in (200, 405):
                found_provision_endpoints.append(path)
                if base_url.startswith("https://") and resp.status_code == 200:
                    http_url = "http://" + base_url.split("://", 1)[1].rstrip("/") + path
                    try:
                        with httpx.Client(follow_redirects=False, timeout=5, verify=False) as nr_c:
                            nr_resp = nr_c.get(http_url)
                            if nr_resp.status_code not in (301, 302, 307, 308):
                                results.append({{
                                    "title": "Provisioning endpoint does not enforce HTTPS",
                                    "description": f"{{path}} served over HTTP without redirect (status {{nr_resp.status_code}})",
                                    "severity": "medium",
                                    "data": {{"endpoint": path, "http_status": nr_resp.status_code}},
                                }})
                    except Exception:
                        pass
        except Exception:
            pass
except Exception as e:
    results.append({{"title": "Endpoint discovery error", "description": str(e), "severity": "info", "data": {{"error": str(e)}}}})


# ── Block 2: Privilege Escalation at Provisioning ───────────────────────────────────────────────────

try:
    uid = random.randint(10000, 99999)
    priv_payloads = [
        {{"role": "admin", "username": f"priv_role_{{uid}}", "email": f"priv_role_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
        {{"is_admin": True, "username": f"priv_isadmin_{{uid}}", "email": f"priv_isadmin_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
        {{"account_type": "admin", "username": f"priv_acct_{{uid}}", "email": f"priv_acct_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
        {{"user_type": "administrator", "username": f"priv_utype_{{uid}}", "email": f"priv_utype_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
        {{"admin": 1, "username": f"priv_admin1_{{uid}}", "email": f"priv_admin1_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
        {{"permissions": ["admin"], "username": f"priv_perm_{{uid}}", "email": f"priv_perm_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
        {{"access_level": 999, "username": f"priv_alvl_{{uid}}", "email": f"priv_alvl_{{uid}}@example.com", "password": "T3stP@ssw0rd!"}},
    ]
    inj_keys = ["role", "is_admin", "account_type", "user_type", "admin", "permissions", "access_level"]
    header_variants = [{{}}] + ([_tester_auth_header] if _tester_auth_header else [])

    for ep in found_provision_endpoints:
        url = base_url.rstrip("/") + ep
        for payload, inj_key in zip(priv_payloads, inj_keys):
            for extra_headers in header_variants:
                try:
                    c = make_client()
                    resp = safe_request("POST", url, c, json=payload, headers=extra_headers)
                    c.close()
                    if resp is None:
                        continue
                    if resp.status_code in (200, 201):
                        results.append({{
                            "title": "Privilege escalation parameter accepted at provisioning",
                            "description": f"POST to {{ep}} with {{inj_key}}=<elevated> returned {{resp.status_code}}",
                            "severity": "high",
                            "data": {{"endpoint": ep, "injected_field": inj_key, "response_status": resp.status_code, "authenticated": bool(extra_headers)}},
                        }})
                    else:
                        try:
                            body = resp.json()
                            if isinstance(body, dict) and body.get(inj_key) == payload[inj_key]:
                                results.append({{
                                    "title": "Provisioning response reflects elevated role parameter",
                                    "description": f"Response JSON reflects {{inj_key}} with elevated value after POST to {{ep}}",
                                    "severity": "high",
                                    "data": {{"endpoint": ep, "injected_field": inj_key, "reflected_value": str(payload[inj_key])}},
                                }})
                        except Exception:
                            pass
                except Exception:
                    pass
except Exception as e:
    results.append({{"title": "Privilege escalation test error", "description": str(e), "severity": "info", "data": {{"error": str(e)}}}})


# ── Block 3: Unauthenticated Admin Provisioning Access ────────────────────────────────────────────

try:
    uid = random.randint(10000, 99999)
    admin_paths = [
        "/api/admin/users", "/admin/api/users", "/api/internal/users", "/internal/api/users",
        "/api/v1/provision", "/api/provision", "/admin/accounts", "/api/v1/accounts",
    ]
    for ep in admin_paths:
        url = base_url.rstrip("/") + ep
        try:
            c = make_client()
            resp_get = safe_request("GET", url, c)
            c.close()
            if resp_get is not None and resp_get.status_code not in (401, 403, 404, 302):
                results.append({{
                    "title": "Admin provisioning endpoint accessible without authentication",
                    "description": f"GET {{ep}} returned {{resp_get.status_code}} without authentication",
                    "severity": "high",
                    "data": {{"endpoint": ep, "method": "GET", "status_code": resp_get.status_code}},
                }})
            c2 = make_client()
            resp_post = safe_request("POST", url, c2, json={{
                "username": f"unauth_{{uid}}", "email": f"unauth_{{uid}}@example.com", "password": "T3stP@ssw0rd!",
            }})
            c2.close()
            if resp_post is not None and resp_post.status_code in (200, 201):
                results.append({{
                    "title": "Account creation without authentication",
                    "description": f"POST to {{ep}} created account without auth (status {{resp_post.status_code}})",
                    "severity": "critical",
                    "data": {{"endpoint": ep, "method": "POST", "status_code": resp_post.status_code}},
                }})
        except Exception:
            pass
except Exception as e:
    results.append({{"title": "Unauthenticated provisioning access test error", "description": str(e), "severity": "info", "data": {{"error": str(e)}}}})


# ── Block 4: Two-Account De-Provisioning IDOR ───────────────────────────────────────────────────

if not tester_token or not testing_user_username:
    results.append({{
        "title": "Two-account IDOR tests skipped — only one account configured",
        "description": "Set both Account 1 (tester) and Account 2 (testing_user) credentials in the campaign builder to enable IDOR de-provisioning tests",
        "severity": "info",
        "data": {{"has_tester_token": bool(tester_token), "has_testing_user": bool(testing_user_username)}},
    }})
else:
    try:
        id_candidates = [testing_user_username, testing_user_email] + [str(i) for i in range(1, 6)] + ["me", "self"]
        deprovision_path_templates = [
            "/api/users/{{id}}", "/api/v1/users/{{id}}", "/api/accounts/{{id}}",
            "/api/users/{{id}}/suspend", "/api/users/{{id}}/ban",
            "/api/users/{{id}}/deactivate", "/api/users/{{id}}/delete",
        ]
        for id_val in id_candidates:
            for path_tmpl in deprovision_path_templates:
                ep = path_tmpl.format(id=id_val)
                url = base_url.rstrip("/") + ep
                try:
                    with make_client() as c:
                        resp = safe_request("DELETE", url, c, headers=_tester_auth_header)
                    if resp is not None and resp.status_code in (200, 204):
                        results.append({{
                            "title": "IDOR: Account de-provisioning another user\'s account",
                            "description": f"DELETE {{ep}} using Account 1 token succeeded ({{resp.status_code}}) — IDOR against testing_user",
                            "severity": "critical",
                            "data": {{"endpoint": ep, "id_used": id_val, "status_code": resp.status_code}},
                        }})
                    with make_client() as c2:
                        resp2 = safe_request("PATCH", url, c2, json={{"status": "suspended"}}, headers=_tester_auth_header)
                    if resp2 is not None and resp2.status_code in (200, 204):
                        results.append({{
                            "title": "IDOR: Account suspension of another user",
                            "description": f"PATCH {{ep}} status=suspended with Account 1 token succeeded ({{resp2.status_code}})",
                            "severity": "critical",
                            "data": {{"endpoint": ep, "id_used": id_val, "status_code": resp2.status_code}},
                        }})
                    with make_client() as c3:
                        resp3 = safe_request("DELETE", url, c3)
                    if resp3 is not None and resp3.status_code in (200, 204):
                        results.append({{
                            "title": "Unauthenticated account deletion",
                            "description": f"DELETE {{ep}} without auth succeeded ({{resp3.status_code}})",
                            "severity": "critical",
                            "data": {{"endpoint": ep, "id_used": id_val, "status_code": resp3.status_code}},
                        }})
                except Exception:
                    pass
        # Self-de-provision check
        for path_tmpl in ["/api/users/{{id}}", "/api/v1/users/{{id}}"]:
            for id_val in [tester_username, "me", "self"]:
                if not id_val:
                    continue
                ep = path_tmpl.format(id=id_val)
                url = base_url.rstrip("/") + ep
                try:
                    with make_client() as c:
                        resp = safe_request("DELETE", url, c, headers=_tester_auth_header)
                    if resp is not None and resp.status_code in (200, 204):
                        results.append({{
                            "title": "Self de-provisioning allowed without re-authentication",
                            "description": f"DELETE {{ep}} for own account succeeded without re-auth ({{resp.status_code}})",
                            "severity": "medium",
                            "data": {{"endpoint": ep, "id_used": id_val, "status_code": resp.status_code}},
                        }})
                except Exception:
                    pass
    except Exception as e:
        results.append({{"title": "IDOR de-provisioning test error", "description": str(e), "severity": "info", "data": {{"error": str(e)}}}})


# ── Block 5: Provisioning Workflow Bypass ───────────────────────────────────────────────────────────────────────

try:
    uid = random.randint(10000, 99999)
    activation_paths = [
        "/activate", "/api/activate", "/api/v1/activate",
        "/verify", "/api/verify", "/api/v1/verify",
        "/confirm", "/api/confirm", "/api/v1/confirm",
        "/api/users/activate", "/api/v1/users/activate",
    ]
    for ep in activation_paths:
        url = base_url.rstrip("/") + ep
        for test_type, payload in [
            ("fake_token", {{"user_id": "999999", "token": f"fake_{{uid}}"}}),
            ("empty_token", {{"user_id": "999999", "token": ""}}),
            ("missing_token", {{"user_id": "999999"}}),
        ]:
            try:
                c = make_client()
                resp = safe_request("POST", url, c, json=payload)
                c.close()
                if resp is not None and resp.status_code in (200, 201):
                    if "error" not in resp.text.lower() and "invalid" not in resp.text.lower():
                        results.append({{
                            "title": "Account activation bypass — fake token accepted",
                            "description": f"POST to {{ep}} with {{test_type}} returned {{resp.status_code}} without error indicators",
                            "severity": "high",
                            "data": {{"endpoint": ep, "test_type": test_type, "status_code": resp.status_code}},
                        }})
            except Exception:
                pass
    for ep in ["/api/users/999999/status", "/api/v1/users/999999/status"]:
        url = base_url.rstrip("/") + ep
        try:
            c = make_client()
            resp = safe_request("POST", url, c, json={{"status": "active"}})
            c.close()
            if resp is not None and resp.status_code in (200, 201):
                results.append({{
                    "title": "Direct state promotion without workflow",
                    "description": f"POST to {{ep}} with status=active succeeded without auth ({{resp.status_code}})",
                    "severity": "high",
                    "data": {{"endpoint": ep, "status_code": resp.status_code}},
                }})
        except Exception:
            pass
except Exception as e:
    results.append({{"title": "Workflow bypass test error", "description": str(e), "severity": "info", "data": {{"error": str(e)}}}})


# ── Block 6: Rate Limiting & Audit Trail ──────────────────────────────────────────────────────────────────────────

try:
    rate_limit_patterns = re.compile(r"(rate.?limit|too many|slow down|throttl)", re.IGNORECASE)
    captcha_patterns = re.compile(r"(g-recaptcha|h-captcha|cf-turnstile|data-sitekey|hcaptcha)", re.IGNORECASE)

    for ep in found_provision_endpoints:
        url = base_url.rstrip("/") + ep
        uid = random.randint(10000, 99999)
        rate_limited = False
        try:
            c = make_client()
            page_resp = safe_request("GET", url, c)
            c.close()
            if page_resp is not None and not captcha_patterns.search(page_resp.text):
                results.append({{
                    "title": "No bot protection detected on provisioning endpoint",
                    "description": f"No CAPTCHA indicators found on {{ep}}",
                    "severity": "low",
                    "data": {{"endpoint": ep}},
                }})
        except Exception:
            pass
        for i in range(15):
            try:
                c = make_client()
                resp = safe_request("POST", url, c, json={{
                    "username": f"ratelimit_{{uid}}_{{i}}",
                    "email": f"ratelimit_{{uid}}_{{i}}@example.com",
                    "password": "T3stP@ssw0rd!",
                }})
                c.close()
                if resp is None:
                    continue
                if resp.status_code in (429, 503) or rate_limit_patterns.search(resp.text):
                    rate_limited = True
                    break
            except Exception:
                pass
        if not rate_limited:
            results.append({{
                "title": "No rate limiting on provisioning endpoint",
                "description": f"{{ep}} did not trigger rate limiting after 15 rapid provisioning attempts",
                "severity": "medium",
                "data": {{"endpoint": ep, "attempts_before_check": 15}},
            }})

    audit_paths = ["/api/audit/users", "/api/v1/audit", "/api/logs", "/admin/audit", "/api/admin/logs"]
    audit_found = False
    for ep in audit_paths:
        url = base_url.rstrip("/") + ep
        try:
            c = make_client()
            resp = safe_request("GET", url, c)
            c.close()
            if resp is None:
                continue
            if resp.status_code == 200:
                audit_found = True
                results.append({{
                    "title": "Audit log endpoint accessible without authentication",
                    "description": f"GET {{ep}} returned 200 without auth — provisioning audit logs may be exposed",
                    "severity": "high",
                    "data": {{"endpoint": ep, "status_code": resp.status_code}},
                }})
        except Exception:
            pass
    if not audit_found:
        results.append({{
            "title": "No audit trail endpoint detected for provisioning",
            "description": "None of the standard audit log paths returned a 200 response",
            "severity": "info",
            "data": {{"paths_checked": audit_paths}},
        }})
except Exception as e:
    results.append({{"title": "Rate limiting and audit test error", "description": str(e), "severity": "info", "data": {{"error": str(e)}}}})


print(json.dumps(results))
'''
        return ["python3", "-c", script]

    def parse_output(self, stdout: str) -> list:
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
