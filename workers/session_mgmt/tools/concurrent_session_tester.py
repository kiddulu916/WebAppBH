"""Concurrent session limit testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class ConcurrentSessionTester(SessionMgmtTool):
    """Test concurrent session limits (WSTG-SESS-006)."""

    name = "concurrent_session_tester"
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
    sessions = []
    session_tokens = []
    login_paths = ["/login", "/auth/login", "/api/login", "/signin", "/wp-login.php", "/user/login"]

    # Test 1: Create multiple sessions and check if they all remain valid
    if credentials and credentials.get("username") and credentials.get("password"):
        max_sessions = 5

        for i in range(max_sessions):
            client = httpx.Client(verify=False, follow_redirects=True, timeout=10)

            logged_in = False
            for path in login_paths:
                try:
                    resp = client.post(
                        base_url.rstrip("/") + path,
                        data={{"username": credentials["username"], "password": credentials["password"]}},
                        timeout=10
                    )
                    if resp.status_code in (200, 302, 301):
                        session_token = None
                        for name, value in resp.cookies.items():
                            if any(kw in name.lower() for kw in ["session", "sid", "token", "auth"]):
                                session_token = value
                                break

                        if session_token:
                            sessions.append({{
                                "client": client,
                                "token": session_token,
                                "session_num": i + 1
                            }})
                            session_tokens.append(session_token)
                            logged_in = True
                            break
                except Exception:
                    pass

            if not logged_in:
                client.close()

        # Test 2: Verify all sessions are still valid
        valid_sessions = 0
        invalidated_sessions = 0

        for session in sessions:
            try:
                resp = session["client"].get(base_url, timeout=10)
                if resp.status_code not in (401, 403):
                    body_lower = resp.text.lower()
                    auth_indicators = ["login", "sign in", "log in", "authenticate", "session expired"]
                    if not any(ind in body_lower for ind in auth_indicators):
                        valid_sessions += 1
                    else:
                        invalidated_sessions += 1
                else:
                    invalidated_sessions += 1
            except Exception:
                invalidated_sessions += 1

        if valid_sessions > 1:
            results.append({{
                "title": "Multiple concurrent sessions allowed",
                "description": f"Found {{valid_sessions}} valid concurrent sessions for the same user. Consider implementing session limits to reduce the impact of session hijacking.",
                "severity": "medium",
                "data": {{
                    "total_sessions_created": len(sessions),
                    "valid_sessions": valid_sessions,
                    "invalidated_sessions": invalidated_sessions,
                    "concurrent_sessions_allowed": valid_sessions > 1
                }}
            }})

            # Check if old sessions get invalidated when new ones are created
            if len(session_tokens) >= 2:
                # Test if the first session is still valid after creating multiple sessions
                first_session = sessions[0]
                try:
                    resp = first_session["client"].get(base_url, timeout=10)
                    if resp.status_code not in (401, 403):
                        results.append({{
                            "title": "Old sessions not invalidated on new login",
                            "description": "Previous sessions remain valid after new logins. Consider invalidating old sessions when a new session is created.",
                            "severity": "medium",
                            "data": {{
                                "first_session_still_valid": True,
                                "recommendation": "Invalidate previous sessions when a new session is created"
                            }}
                        }})
                except Exception:
                    pass
        elif valid_sessions == 1 and len(sessions) > 1:
            results.append({{
                "title": "Session limit enforced",
                "description": f"Only 1 session remained valid out of {{len(sessions)}} created. The application enforces single-session policy.",
                "severity": "info",
                "data": {{
                    "total_sessions_created": len(sessions),
                    "valid_sessions": valid_sessions,
                    "session_limit": 1
                }}
            }})

        # Clean up
        for session in sessions:
            try:
                session["client"].close()
            except Exception:
                pass

    # Test 3: Check for session binding to IP/User-Agent
    try:
        client = httpx.Client(verify=False, follow_redirects=True, timeout=10)
        resp = client.get(base_url, timeout=10)

        # Check for security headers that indicate session binding
        binding_indicators = []
        for header_name, header_value in resp.headers.items():
            if header_name.lower() in ["x-session-bound", "x-client-fingerprint", "x-device-id"]:
                binding_indicators.append({{
                    "header": header_name,
                    "value": header_value[:50]
                }})

        if binding_indicators:
            results.append({{
                "title": "Session binding indicators detected",
                "description": f"Found headers that may indicate session binding to client characteristics: {{[b['header'] for b in binding_indicators]}}",
                "severity": "info",
                "data": {{
                    "binding_indicators": binding_indicators
                }}
            }})
        else:
            results.append({{
                "title": "No session binding detected",
                "description": "No indicators of session binding to IP address or User-Agent found. Sessions may be usable from different clients.",
                "severity": "low",
                "data": {{
                    "binding_detected": False,
                    "recommendation": "Consider binding sessions to client IP or User-Agent for additional security"
                }}
            }})

        client.close()
    except Exception:
        pass

    # Test 4: Check for concurrent session notification
    try:
        client = httpx.Client(verify=False, follow_redirects=True, timeout=10)
        resp = client.get(base_url, timeout=10)
        body_lower = resp.text.lower()

        notification_keywords = ["concurrent session", "session limit", "too many sessions", "active sessions", "session management"]
        found_notifications = [kw for kw in notification_keywords if kw in body_lower]

        if found_notifications:
            results.append({{
                "title": "Concurrent session management UI detected",
                "description": f"Found references to session management in the application: {{found_notifications}}",
                "severity": "info",
                "data": {{
                    "keywords_found": found_notifications
                }}
            }})
    except Exception:
        pass

    if not results:
        results.append({{
            "title": "Concurrent session test completed",
            "description": "No concurrent session issues detected. Manual testing with real credentials recommended.",
            "severity": "info",
            "data": {{
                "tests_performed": ["multiple_session_creation", "session_validation", "session_binding", "session_notification"]
            }}
        }})

except Exception as e:
    results.append({{
        "title": "Concurrent session test error",
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
