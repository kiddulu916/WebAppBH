"""Session puzzling / overloading testing tool (WSTG-SESS-008)."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class SessionPuzzlingTester(SessionMgmtTool):
    """Test for session puzzling / session variable overloading (WSTG-SESS-008).

    Session puzzling occurs when the same session variable is used for
    different purposes across multiple flows, allowing attackers to bypass
    authentication or authorization by triggering one flow to set a session
    variable then accessing another flow that trusts it.
    """

    name = "session_puzzling_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        target_url = getattr(target, "target_value", str(target))
        base_url = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"

        script = f'''
import httpx
import json

results = []
base_url = "{base_url}"

try:
    # Test session variable overloading by checking if session state
    # from one flow leaks into another

    # Flow 1: Access password reset / registration to set session vars
    init_paths = ["/password-reset", "/forgot-password", "/register",
                  "/signup", "/api/password/reset", "/account/recover"]
    # Flow 2: Try to access authenticated areas with the same session
    protected_paths = ["/dashboard", "/admin", "/account", "/profile",
                       "/api/user", "/settings", "/api/me"]

    client = httpx.Client(follow_redirects=False, timeout=10, verify=False)

    for init_path in init_paths:
        try:
            # Step 1: Hit the init path to get a session
            resp1 = client.get(base_url.rstrip("/") + init_path)
            if resp1.status_code >= 400:
                continue

            session_cookies = dict(resp1.cookies)
            if not session_cookies:
                continue

            # Step 2: Try accessing protected paths with that session
            for protected_path in protected_paths:
                try:
                    resp2 = client.get(
                        base_url.rstrip("/") + protected_path,
                        cookies=session_cookies,
                    )

                    # If we get 200 on a protected path with a session from
                    # an unauthenticated flow, that might be session puzzling
                    if resp2.status_code == 200:
                        body = resp2.text.lower()
                        # Look for indicators of authenticated content
                        auth_indicators = ["logout", "sign out", "my account",
                                           "dashboard", "settings", "profile"]
                        found_indicators = [i for i in auth_indicators if i in body]

                        if found_indicators:
                            results.append({{
                                "title": f"Potential session puzzling: {{init_path}} -> {{protected_path}}",
                                "description": (
                                    f"Session from {{init_path}} grants access to {{protected_path}}. "
                                    f"Authenticated indicators found: {{', '.join(found_indicators)}}"
                                ),
                                "severity": "high",
                                "data": {{
                                    "init_path": init_path,
                                    "protected_path": protected_path,
                                    "init_status": resp1.status_code,
                                    "protected_status": resp2.status_code,
                                    "auth_indicators": found_indicators,
                                    "session_cookies": list(session_cookies.keys())
                                }}
                            }})
                except Exception:
                    pass

        except Exception:
            pass

    # Test POST-based session puzzling
    post_init_paths = [
        ("/password-reset", {{"email": "test@test.com"}}),
        ("/register", {{"username": "test", "email": "test@test.com"}}),
    ]
    for path, data in post_init_paths:
        try:
            resp = client.post(base_url.rstrip("/") + path, data=data)
            if resp.status_code < 400 and resp.cookies:
                session_cookies = dict(resp.cookies)
                for protected_path in protected_paths[:3]:
                    try:
                        resp2 = client.get(
                            base_url.rstrip("/") + protected_path,
                            cookies=session_cookies,
                        )
                        if resp2.status_code == 200:
                            body = resp2.text.lower()
                            auth_indicators = ["logout", "sign out", "my account"]
                            found = [i for i in auth_indicators if i in body]
                            if found:
                                results.append({{
                                    "title": f"POST-based session puzzling: {{path}} -> {{protected_path}}",
                                    "description": (
                                        f"POST to {{path}} creates session granting access to {{protected_path}}"
                                    ),
                                    "severity": "high",
                                    "data": {{
                                        "init_path": path,
                                        "protected_path": protected_path,
                                        "auth_indicators": found
                                    }}
                                }})
                    except Exception:
                        pass
        except Exception:
            pass

    client.close()

    if not results:
        results.append({{
            "title": "Session puzzling test",
            "description": "No session puzzling / overloading vulnerabilities detected",
            "severity": "info",
            "data": {{
                "init_paths_tested": len(init_paths) + len(post_init_paths),
                "protected_paths_tested": len(protected_paths)
            }}
        }})

except Exception as e:
    results.append({{
        "title": "Session puzzling test error",
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
