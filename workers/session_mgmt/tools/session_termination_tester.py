"""Session invalidation on logout testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class SessionTerminationTester(SessionMgmtTool):
    """Test session invalidation on logout (WSTG-SESS-007)."""

    name = "session_termination_tester"
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
    client = httpx.Client(verify=False, follow_redirects=False, timeout=10)
    session_token = None
    session_cookie_name = None
    logout_path = None

    # Step 1: Authenticate to get a session
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

    # If no credentials, try to get a session from root
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
        logout_paths = ["/logout", "/auth/logout", "/api/logout", "/signout", "/wp-login.php?action=logout", "/user/logout", "/account/logout", "/session/destroy"]

        # Also check the page for logout links
        try:
            resp = client.get(base_url, timeout=10)
            body = resp.text
            import re
            logout_links = re.findall(r'href=["\']([^"\']*(?:logout|signout|logoff|session/destroy)[^"\']*)["\']', body, re.IGNORECASE)
            if logout_links:
                logout_paths = logout_links + logout_paths
        except Exception:
            pass

        # Step 3: Try each logout path
        logout_worked = False
        logout_response_status = None

        for path in logout_paths:
            try:
                # Save the session token before logout
                token_before_logout = session_token

                # Perform logout
                resp = client.get(base_url.rstrip("/") + path, timeout=10)
                logout_response_status = resp.status_code

                # Check if session cookie was cleared or changed
                new_token = None
                cookie_cleared = False
                for name, value in resp.cookies.items():
                    if name.lower() == (session_cookie_name or "session").lower():
                        if value == "" or value != token_before_logout:
                            cookie_cleared = True
                        new_token = value

                # Verify session is invalid after logout
                client2 = httpx.Client(verify=False, follow_redirects=False, timeout=10)
                if session_cookie_name:
                    client2.cookies.set(session_cookie_name, token_before_logout)

                resp2 = client2.get(base_url, timeout=10)

                # Check if the old token still works
                body_lower = resp2.text.lower()
                auth_indicators = ["login", "sign in", "log in", "authenticate", "session expired", "logged out"]
                is_authenticated = not any(ind in body_lower for ind in auth_indicators) and resp2.status_code not in (401, 403)

                if not is_authenticated or cookie_cleared:
                    logout_worked = True
                    logout_path = path

                    results.append({{
                        "title": "Session properly invalidated after logout",
                        "description": f"Logout at '{{path}}' successfully invalidated the session. Old session token is no longer valid.",
                        "severity": "info",
                        "data": {{
                            "logout_path": path,
                            "logout_status_code": logout_response_status,
                            "cookie_cleared": cookie_cleared,
                            "old_token_invalid": not is_authenticated,
                            "session_cookie_name": session_cookie_name
                        }}
                    }})
                    break
                else:
                    results.append({{
                        "title": "Session NOT invalidated after logout",
                        "description": f"Logout at '{{path}}' did not properly invalidate the session. The old session token is still valid after logout, allowing session reuse.",
                        "severity": "high",
                        "data": {{
                            "logout_path": path,
                            "logout_status_code": logout_response_status,
                            "cookie_cleared": cookie_cleared,
                            "old_token_still_valid": True,
                            "session_cookie_name": session_cookie_name,
                            "vulnerable": True
                        }}
                    }})
                    logout_worked = True
                    logout_path = path
                    break

                client2.close()
            except Exception:
                pass

        if not logout_worked:
            results.append({{
                "title": "Could not find working logout endpoint",
                "description": "Tested multiple logout paths but could not verify session termination. Manual testing recommended.",
                "severity": "info",
                "data": {{
                    "paths_tested": logout_paths[:5],
                    "session_cookie_name": session_cookie_name
                }}
            }})

        # Step 4: Test session invalidation after password change (if credentials provided)
        if credentials and credentials.get("username") and credentials.get("password"):
            password_change_paths = ["/api/password/change", "/api/user/password", "/account/password", "/user/password", "/settings/password"]
            for path in password_change_paths:
                try:
                    resp = client.post(
                        base_url.rstrip("/") + path,
                        data={{
                            "current_password": credentials["password"],
                            "new_password": credentials["password"] + "_changed"
                        }},
                        timeout=10
                    )
                    if resp.status_code in (200, 302):
                        # Check if session was invalidated
                        resp2 = client.get(base_url, timeout=10)
                        body_lower = resp2.text.lower()
                        if "login" in body_lower or "sign in" in body_lower or resp2.status_code in (401, 403):
                            results.append({{
                                "title": "Session invalidated after password change",
                                "description": f"Session was properly invalidated after password change at '{{path}}'",
                                "severity": "info",
                                "data": {{
                                    "password_change_path": path,
                                    "session_invalidated": True
                                }}
                            }})
                        else:
                            results.append({{
                                "title": "Session NOT invalidated after password change",
                                "description": f"Session remained valid after password change at '{{path}}'. All sessions should be invalidated when a password is changed.",
                                "severity": "high",
                                "data": {{
                                    "password_change_path": path,
                                    "session_invalidated": False
                                }}
                            }})
                        break
                except Exception:
                    pass

        client.close()
    else:
        results.append({{
            "title": "No session token available for termination testing",
            "description": "Could not obtain a session token to test session termination behavior",
            "severity": "info",
            "data": {{"authenticated": bool(credentials)}}
        }})

except Exception as e:
    results.append({{
        "title": "Session termination test error",
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
