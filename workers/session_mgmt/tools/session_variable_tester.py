"""Session variable exposure testing tool (WSTG-SESS-004)."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class SessionVariableTester(SessionMgmtTool):
    """Test for exposed session variables in URLs, logs, and error pages (WSTG-SESS-004)."""

    name = "session_variable_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        target_url = getattr(target, "target_value", str(target))
        base_url = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"

        script = f'''
import httpx
import json
import re

results = []
base_url = "{base_url}"

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    # Check if session tokens appear in URLs (GET parameter leakage)
    test_paths = ["/", "/login", "/dashboard", "/account", "/profile", "/api/user"]
    for path in test_paths:
        try:
            resp = client.get(base_url.rstrip("/") + path)
            final_url = str(resp.url)

            session_params = []
            for param in ["sessionid", "sid", "session", "token", "auth_token",
                          "jsessionid", "phpsessid", "asp.net_sessionid", "csrftoken"]:
                if param in final_url.lower():
                    session_params.append(param)

            if session_params:
                results.append({{
                    "title": f"Session variable exposed in URL: {{path}}",
                    "description": f"Session parameters found in URL: {{', '.join(session_params)}}. "
                                   "This exposes session tokens in browser history, server logs, and Referer headers.",
                    "severity": "high",
                    "data": {{
                        "path": path,
                        "exposed_params": session_params,
                        "url": final_url
                    }}
                }})

            # Check for session data in hidden form fields
            body = resp.text
            hidden_fields = re.findall(
                r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
                body, re.IGNORECASE
            )
            sensitive_hidden = []
            for name, value in hidden_fields:
                if any(kw in name.lower() for kw in ["session", "token", "csrf", "auth", "secret"]):
                    if len(value) > 10:
                        sensitive_hidden.append({{"name": name, "value_length": len(value)}})

            if sensitive_hidden:
                results.append({{
                    "title": f"Session-related hidden fields found: {{path}}",
                    "description": f"Found {{len(sensitive_hidden)}} hidden fields with session-like data",
                    "severity": "info",
                    "data": {{
                        "path": path,
                        "fields": sensitive_hidden
                    }}
                }})

            # Check for session data in response headers
            for header_name, header_value in resp.headers.items():
                if any(kw in header_name.lower() for kw in ["session", "token"]):
                    if len(header_value) > 10:
                        results.append({{
                            "title": f"Session data in response header: {{header_name}}",
                            "description": f"Header {{header_name}} contains session-like data ({{len(header_value)}} chars)",
                            "severity": "medium",
                            "data": {{
                                "path": path,
                                "header": header_name,
                                "value_length": len(header_value)
                            }}
                        }})

        except Exception:
            pass

    # Check error pages for session variable leakage
    error_paths = ["/nonexistent_" + "a" * 50, "/api/../../etc/passwd", "/%00"]
    for path in error_paths:
        try:
            resp = client.get(base_url.rstrip("/") + path)
            body = resp.text.lower()
            if any(kw in body for kw in ["session_id", "sessionid", "phpsessid",
                                          "jsessionid", "session_data", "session["]):
                results.append({{
                    "title": "Session variable leaked in error page",
                    "description": f"Error page at {{path}} reveals session variable names or values",
                    "severity": "medium",
                    "data": {{
                        "path": path,
                        "status_code": resp.status_code
                    }}
                }})
        except Exception:
            pass

    client.close()

    if not results:
        results.append({{
            "title": "Session variable exposure test",
            "description": "No exposed session variables detected in URLs, headers, or error pages",
            "severity": "info",
            "data": {{"paths_tested": len(test_paths) + len(error_paths)}}
        }})

except Exception as e:
    results.append({{
        "title": "Session variable test error",
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
