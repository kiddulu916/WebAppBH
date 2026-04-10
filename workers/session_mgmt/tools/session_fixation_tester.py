"""Session fixation vulnerability testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class SessionFixationTester(SessionMgmtTool):
    """Test for session fixation vulnerabilities (WSTG-SESS-004)."""

    name = "session_fixation_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        creds_json = "None"
        if credentials:
            import json as _j
            creds_json = _j.dumps(credentials)

        script = f'''
import httpx
import json

results = []
base_url = "{base_url}"
credentials = {creds_json}

try:
    # Test 1: Check if session ID changes after login
    pre_login_token = None
    pre_login_cookie_name = None
    post_login_token = None
    post_login_cookie_name = None

    # Step 1: Get a session token before login
    client = httpx.Client(verify=False, follow_redirects=True, timeout=10)
    try:
        resp = client.get(base_url)
        for name, value in resp.cookies.items():
            if any(kw in name.lower() for kw in ["session", "sid", "token", "auth", "jsessionid", "phpsessid"]):
                pre_login_token = value
                pre_login_cookie_name = name
                break
    except Exception:
        pass

    # Step 2: Attempt login with the same client (same session)
    if credentials and credentials.get("username") and credentials.get("password"):
        login_paths = ["/login", "/auth/login", "/api/login", "/signin", "/wp-login.php", "/user/login"]
        for path in login_paths:
            try:
                resp = client.post(
                    base_url.rstrip("/") + path,
                    data={{"username": credentials["username"], "password": credentials["password"]}},
                    timeout=10
                )
                if resp.status_code in (200, 302, 301):
                    for name, value in resp.cookies.items():
                        if any(kw in name.lower() for kw in ["session", "sid", "token", "auth"]):
                            post_login_token = value
                            post_login_cookie_name = name
                            break
                if post_login_token:
                    break
            except Exception:
                pass

        # Analyze session fixation
        if pre_login_token and post_login_token:
            if pre_login_token == post_login_token:
                results.append({{
                    "title": "Session fixation vulnerability - token unchanged after login",
                    "description": f"The session token '{{pre_login_cookie_name}}' remains the same before and after authentication. An attacker could set a known session token before the victim logs in, then hijack the authenticated session.",
                    "severity": "high",
                    "data": {{
                        "cookie_name": pre_login_cookie_name,
                        "pre_login_token": pre_login_token[:20] + "...",
                        "post_login_token": post_login_token[:20] + "...",
                        "token_changed": False,
                        "vulnerable": True
                    }}
                }})
            else:
                results.append({{
                    "title": "Session token regenerated after login",
                    "description": f"The session token changed after authentication, indicating proper session fixation protection.",
                    "severity": "info",
                    "data": {{
                        "cookie_name": pre_login_cookie_name,
                        "token_changed": True,
                        "vulnerable": False
                    }}
                }})
        elif pre_login_token and not post_login_token:
            results.append({{
                "title": "Session token lost after login",
                "description": "A session token was present before login but not after. This may indicate improper session handling.",
                "severity": "medium",
                "data": {{
                    "pre_login_token": pre_login_token[:20] + "...",
                    "post_login_token": None
                }}
            }})

    # Test 2: Check if session ID can be set via URL parameter
    fixation_params = ["session", "session_id", "sid", "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "token", "auth_token"]
    fixation_results = []

    for param in fixation_params:
        try:
            test_token = "fixation_test_" + param
            url = base_url.rstrip("/") + f"?{{param}}={{test_token}}"
            resp = client.get(url, timeout=10)

            # Check if the server accepted our session token
            for name, value in resp.cookies.items():
                if value == test_token or (name.lower() == param.lower() and value == test_token):
                    fixation_results.append({{
                        "param": param,
                        "accepted": True
                    }})
                    break
        except Exception:
            pass

    if fixation_results:
        results.append({{
            "title": "Session fixation via URL parameter possible",
            "description": f"The application accepts session identifiers via URL parameters: {{[r['param'] for r in fixation_results]}}. This allows attackers to fixate session tokens.",
            "severity": "high",
            "data": {{
                "vulnerable_params": [r["param"] for r in fixation_results],
                "test_tokens_used": fixation_results
            }}
        }})

    # Test 3: Check if session ID can be set via custom cookie
    custom_token = "attacker_controlled_session_12345"
    try:
        client2 = httpx.Client(verify=False, follow_redirects=True, timeout=10)
        client2.cookies.set(pre_login_cookie_name or "session", custom_token)
        resp = client2.get(base_url, timeout=10)

        # Check if the server used our custom token
        for name, value in resp.cookies.items():
            if name.lower() == (pre_login_cookie_name or "session").lower():
                if value == custom_token:
                    results.append({{
                        "title": "Session fixation via cookie injection possible",
                        "description": f"The application accepts externally set session cookies. An attacker can set a known session token before the victim authenticates.",
                        "severity": "high",
                        "data": {{
                            "cookie_name": pre_login_cookie_name or "session",
                            "custom_token_accepted": True
                        }}
                    }})
                else:
                    results.append({{
                        "title": "Session token regenerated on suspicious activity",
                        "description": "The application regenerated the session token when presented with an externally set cookie, indicating fixation protection.",
                        "severity": "info",
                        "data": {{
                            "cookie_name": pre_login_cookie_name or "session",
                            "custom_token_accepted": False,
                            "token_regenerated": True
                        }}
                    }})
                break
    except Exception:
        pass

    # Test 4: Check for session token in URL (URL-based session management)
    try:
        resp = client.get(base_url, timeout=10)
        body = resp.text
        url_session_patterns = ["session=", "sid=", "PHPSESSID=", "JSESSIONID=", "token="]
        found_in_url = [p for p in url_session_patterns if p in body and "href" in body.split(p)[0].split(">")[-1] if ">" in body.split(p)[0]]

        if found_in_url:
            results.append({{
                "title": "Session token may be passed via URL",
                "description": f"Found potential session token references in URLs: {{found_in_url}}. URL-based session management is vulnerable to fixation and leakage via Referer headers.",
                "severity": "high",
                "data": {{
                    "url_session_patterns": found_in_url
                }}
            }})
    except Exception:
        pass

    if not results:
        results.append({{
            "title": "Session fixation test completed",
            "description": "No obvious session fixation vulnerabilities detected. Manual testing with real credentials recommended.",
            "severity": "info",
            "data": {{
                "tests_performed": ["post_login_token_change", "url_parameter_fixation", "cookie_injection", "url_session_tokens"]
            }}
        }})

    client.close()

except Exception as e:
    results.append({{
        "title": "Session fixation test error",
        "description": str(e),
        "severity": "info",
        "data": {{"error": str(e)}}
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
