"""Logout functionality session clearing testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class LogoutFunctionalityTester(SessionMgmtTool):
    """Test logout properly clears session (WSTG-SESS-009)."""

    name = "logout_functionality_tester"
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
import re

results = []
base_url = "{base_url}"
credentials = {creds_json}

try:
    client = httpx.Client(verify=False, follow_redirects=False, timeout=10)
    session_token = None
    session_cookie_name = None

    # Step 1: Get a session
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
                            session_token = value
                            session_cookie_name = name
                            break
                    if session_token:
                        break
            except Exception:
                pass

    if not session_token:
        try:
            resp = client.get(base_url, timeout=10)
            for name, value in resp.cookies.items():
                if any(kw in name.lower() for kw in ["session", "sid", "token", "auth"]):
                    session_token = value
                    session_cookie_name = name
                    break
        except Exception:
            pass

    if session_token:
        # Step 2: Find logout endpoint
        logout_paths = ["/logout", "/auth/logout", "/api/logout", "/signout", "/user/logout", "/account/logout", "/session/destroy"]

        # Check page for logout links
        try:
            resp = client.get(base_url, timeout=10)
            body = resp.text
            logout_links = re.findall(r'href=["\\']([^"\\']*(?:logout|signout|logoff)[^"\\']*)["\\']', body, re.IGNORECASE)
            if logout_links:
                logout_paths = logout_links + logout_paths
        except Exception:
            pass

        # Step 3: Test logout functionality
        for path in logout_paths:
            try:
                token_before = session_token

                # Perform logout
                resp = client.get(base_url.rstrip("/") + path, timeout=10)
                logout_status = resp.status_code

                # Check response headers for cache control
                cache_headers = {{}}
                for h in ["Cache-Control", "Pragma", "Expires"]:
                    if h in resp.headers:
                        cache_headers[h] = resp.headers[h]

                # Check if session cookie was cleared
                cookie_cleared = False
                for name, value in resp.cookies.items():
                    if name.lower() == (session_cookie_name or "session").lower():
                        if value == "" or value != token_before:
                            cookie_cleared = True

                # Test 1: Verify old session token is invalid
                client2 = httpx.Client(verify=False, follow_redirects=False, timeout=10)
                if session_cookie_name:
                    client2.cookies.set(session_cookie_name, token_before)

                resp2 = client2.get(base_url, timeout=10)
                body_lower = resp2.text.lower()
                auth_indicators = ["login", "sign in", "log in", "authenticate", "session expired", "logged out"]
                is_authenticated = not any(ind in body_lower for ind in auth_indicators) and resp2.status_code not in (401, 403)

                if not is_authenticated:
                    results.append({{
                        "title": "Logout properly invalidates session",
                        "description": f"Logout at '{{path}}' successfully invalidated the session. Old token is no longer accepted.",
                        "severity": "info",
                        "data": {{
                            "logout_path": path,
                            "logout_status_code": logout_status,
                            "old_token_invalid": True,
                            "session_cookie_name": session_cookie_name
                        }}
                    }})
                else:
                    results.append({{
                        "title": "Session NOT invalidated after logout",
                        "description": f"Logout at '{{path}}' did not invalidate the session. The old session token is still valid, allowing session reuse after logout.",
                        "severity": "high",
                        "data": {{
                            "logout_path": path,
                            "logout_status_code": logout_status,
                            "old_token_still_valid": True,
                            "session_cookie_name": session_cookie_name,
                            "vulnerable": True
                        }}
                    }})

                client2.close()

                # Test 2: Check cache control headers on logout response
                has_no_cache = False
                has_no_store = False
                for header_name, header_value in resp.headers.items():
                    if header_name.lower() == "cache-control":
                        if "no-cache" in header_value.lower():
                            has_no_cache = True
                        if "no-store" in header_value.lower():
                            has_no_store = True

                if not has_no_cache and not has_no_store:
                    results.append({{
                        "title": "Missing cache control on logout response",
                        "description": f"Logout response at '{{path}}' does not include Cache-Control: no-cache or no-store headers. This may allow browsers to cache authenticated pages.",
                        "severity": "medium",
                        "data": {{
                            "logout_path": path,
                            "cache_headers": cache_headers,
                            "has_no_cache": has_no_cache,
                            "has_no_store": has_no_store,
                            "recommendation": "Add Cache-Control: no-store, no-cache, must-revalidate to logout responses"
                        }}
                    }})

                # Test 3: Check for CSRF on logout
                # Test if logout can be triggered via GET (should use POST)
                client3 = httpx.Client(verify=False, follow_redirects=False, timeout=10)
                try:
                    resp3 = client3.get(base_url.rstrip("/") + path, timeout=10)
                    if resp3.status_code in (200, 302, 301):
                        results.append({{
                            "title": "Logout accessible via GET request",
                            "description": f"Logout at '{{path}}' is accessible via GET request. This makes it vulnerable to CSRF attacks via malicious links or images.",
                            "severity": "medium",
                            "data": {{
                                "logout_path": path,
                                "method": "GET",
                                "status_code": resp3.status_code,
                                "recommendation": "Use POST for logout endpoints to prevent CSRF via GET requests"
                            }}
                        }})
                except Exception:
                    pass

                # Test if logout accepts POST without CSRF token
                try:
                    resp4 = client3.post(base_url.rstrip("/") + path, timeout=10)
                    if resp4.status_code in (200, 302, 301):
                        body_lower = resp4.text.lower()
                        csrf_error = any(ind in body_lower for ind in ["csrf", "token", "invalid", "missing"])
                        if not csrf_error:
                            results.append({{
                                "title": "Logout accepts POST without CSRF token",
                                "description": f"Logout at '{{path}}' accepts POST requests without CSRF token validation.",
                                "severity": "medium",
                                "data": {{
                                    "logout_path": path,
                                    "csrf_validation": False,
                                    "recommendation": "Implement CSRF token validation for logout endpoint"
                                }}
                            }})
                except Exception:
                    pass

                client3.close()

                # Test 4: Check for session token in URL after logout
                try:
                    resp5 = client.get(base_url.rstrip("/") + path, timeout=10)
                    if resp5.status_code in (301, 302):
                        location = resp5.headers.get("Location", "")
                        if session_token and session_token in location:
                            results.append({{
                                "title": "Session token exposed in redirect URL after logout",
                                "description": f"Logout redirects to a URL containing the session token. This may expose the token in browser history, logs, or Referer headers.",
                                "severity": "high",
                                "data": {{
                                    "logout_path": path,
                                    "redirect_url": location[:100] + "...",
                                    "token_in_url": True
                                }}
                            }})
                except Exception:
                    pass

                # Only test first working logout path
                break

            except Exception:
                pass

        # Test 5: Check for back-button vulnerability (cache control on authenticated pages)
        try:
            client4 = httpx.Client(verify=False, follow_redirects=False, timeout=10)
            if session_cookie_name:
                client4.cookies.set(session_cookie_name, session_token)

            resp = client4.get(base_url, timeout=10)
            cache_control = resp.headers.get("Cache-Control", "")

            if "no-cache" not in cache_control.lower() and "no-store" not in cache_control.lower():
                results.append({{
                    "title": "Missing cache control on authenticated pages",
                    "description": "Authenticated pages do not have Cache-Control: no-store headers. This may allow the browser back button to show authenticated content after logout.",
                    "severity": "medium",
                    "data": {{
                        "cache_control": cache_control,
                        "recommendation": "Add Cache-Control: no-store, no-cache, must-revalidate to authenticated pages"
                    }}
                }})

            client4.close()
        except Exception:
            pass

        client.close()
    else:
        results.append({{
            "title": "No session token available for logout testing",
            "description": "Could not obtain a session token to test logout functionality",
            "severity": "info",
            "data": {{"authenticated": bool(credentials)}}
        }})

except Exception as e:
    results.append({{
        "title": "Logout functionality test error",
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
