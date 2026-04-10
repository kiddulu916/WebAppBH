"""Session idle and absolute timeout testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class SessionTimeoutTester(SessionMgmtTool):
    """Test for session timeout (WSTG-SESS-002)."""

    name = "session_timeout_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import time

results = []
base_url = "{base_url}"

try:
    client = httpx.Client(verify=False, follow_redirects=True, timeout=10)

    # Step 1: Get initial session
    resp = client.get(base_url)
    initial_cookies = dict(resp.cookies)
    session_cookies = {{}}
    for k, v in initial_cookies.items():
        if any(kw in k.lower() for kw in ["session", "sid", "token", "auth", "jsessionid", "phpsessid"]):
            session_cookies[k] = v

    if not session_cookies:
        results.append({{
            "title": "No session cookies found",
            "description": "Could not identify session cookies to test timeout behavior",
            "severity": "info",
            "data": {{"url": base_url}}
        }})
    else:
        # Step 2: Check cookie attributes for timeout indicators
        timeout_findings = []

        for cookie_name, cookie_value in session_cookies.items():
            # Check Set-Cookie headers for Max-Age and Expires
            for header_name, header_value in resp.headers.items():
                if header_name.lower() == "set-cookie" and cookie_name in header_value:
                    has_max_age = "max-age=" in header_value.lower()
                    has_expires = "expires=" in header_value.lower()
                    has_httponly = "httponly" in header_value.lower()
                    has_secure = "secure" in header_value.lower()

                    if not has_max_age and not has_expires:
                        timeout_findings.append({{
                            "title": f"Session cookie '{{cookie_name}}' has no explicit expiration",
                            "description": f"The session cookie '{{cookie_name}}' does not set Max-Age or Expires attribute. It may persist until browser close or indefinitely.",
                            "severity": "medium",
                            "data": {{
                                "cookie_name": cookie_name,
                                "has_max_age": has_max_age,
                                "has_expires": has_expires,
                                "has_httponly": has_httponly,
                                "has_secure": has_secure
                            }}
                        }})

        # Step 3: Test session validity after brief wait (simulated)
        # Make a second request with same cookies to verify session is active
        if session_cookies:
            try:
                resp2 = client.get(base_url)
                still_valid = resp2.status_code == resp.status_code

                # Check if session cookie changed (rotation)
                new_cookies = dict(resp2.cookies)
                session_rotated = False
                for k in session_cookies:
                    if k in new_cookies and new_cookies[k] != session_cookies[k]:
                        session_rotated = True
                        break

                if session_rotated:
                    timeout_findings.append({{
                        "title": "Session token rotation detected",
                        "description": "Session token changed between requests, indicating token rotation is in use",
                        "severity": "info",
                        "data": {{
                            "original_token": session_cookies.get(list(session_cookies.keys())[0], "")[:20] + "...",
                            "rotation_detected": True
                        }}
                    }})
            except Exception:
                pass

        # Step 4: Check for timeout configuration in response
        response_text = resp.text.lower()
        timeout_keywords = ["session.timeout", "session_expiry", "idle_timeout", "maxinactiveinterval"]
        for kw in timeout_keywords:
            if kw in response_text:
                timeout_findings.append({{
                    "title": "Session timeout configuration disclosed",
                    "description": f"Response contains potential session timeout configuration keyword: '{{kw}}'",
                    "severity": "low",
                    "data": {{
                        "keyword": kw,
                        "url": base_url
                    }}
                }})

        if not timeout_findings:
            timeout_findings.append({{
                "title": "Session timeout test completed",
                "description": "No obvious session timeout issues detected. Manual testing recommended for idle timeout verification.",
                "severity": "info",
                "data": {{
                    "cookies_analyzed": list(session_cookies.keys()),
                    "note": "Automated timeout testing requires extended wait periods"
                }}
            }})

        results.extend(timeout_findings)

    client.close()

except Exception as e:
    results.append({{
        "title": "Session timeout test error",
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
