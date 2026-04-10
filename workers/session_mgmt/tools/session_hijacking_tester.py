"""Session hijacking testing tool (WSTG-SESS-009)."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class SessionHijackingTester(SessionMgmtTool):
    """Test for session hijacking vectors (WSTG-SESS-009).

    Checks for conditions that make session hijacking possible:
    weak transport security, missing cookie protections, and
    session token exposure in cross-origin contexts.
    """

    name = "session_hijacking_tester"
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
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    resp = client.get(base_url)

    # 1. Check for session cookies served over HTTP
    if base_url.startswith("http://"):
        session_cookies = []
        for name, value in resp.cookies.items():
            if any(kw in name.lower() for kw in ["session", "sid", "token", "auth"]):
                session_cookies.append(name)
        if session_cookies:
            results.append({{
                "title": "Session cookies served over HTTP",
                "description": f"Session cookies ({{', '.join(session_cookies)}}) served over unencrypted HTTP — trivially interceptable",
                "severity": "critical",
                "data": {{
                    "cookies": session_cookies,
                    "protocol": "http"
                }}
            }})

    # 2. Check Secure flag on session cookies
    for name, value in resp.cookies.items():
        if any(kw in name.lower() for kw in ["session", "sid", "token", "auth", "phpsessid", "jsessionid"]):
            cookie_header = resp.headers.get("set-cookie", "")
            cookie_parts = [c for c in cookie_header.split(",") if name.lower() in c.lower()]

            for cookie_str in cookie_parts:
                cookie_lower = cookie_str.lower()
                issues = []

                if "secure" not in cookie_lower:
                    issues.append("Missing Secure flag — cookie sent over HTTP")
                if "httponly" not in cookie_lower:
                    issues.append("Missing HttpOnly flag — accessible via JavaScript (XSS risk)")
                if "samesite" not in cookie_lower:
                    issues.append("Missing SameSite attribute — vulnerable to CSRF-based session riding")
                elif "samesite=none" in cookie_lower:
                    issues.append("SameSite=None — cookie sent with cross-origin requests")

                if issues:
                    severity = "high" if "Secure" in issues[0] else "medium"
                    results.append({{
                        "title": f"Weak cookie protections: {{name}}",
                        "description": "; ".join(issues),
                        "severity": severity,
                        "data": {{
                            "cookie_name": name,
                            "issues": issues,
                            "raw_header": cookie_str.strip()[:200]
                        }}
                    }})

    # 3. Check for CORS misconfigurations that could enable session theft
    cors_origins = ["https://evil.com", "null", base_url]
    for origin in cors_origins:
        try:
            cors_resp = client.get(base_url, headers={{"Origin": origin}})
            acao = cors_resp.headers.get("access-control-allow-origin", "")
            acac = cors_resp.headers.get("access-control-allow-credentials", "")

            if acao == "*" and acac.lower() == "true":
                results.append({{
                    "title": "CORS wildcard with credentials — session hijacking possible",
                    "description": "Access-Control-Allow-Origin: * with Allow-Credentials: true allows any origin to steal sessions",
                    "severity": "critical",
                    "data": {{
                        "acao": acao,
                        "acac": acac,
                        "test_origin": origin
                    }}
                }})
            elif origin == "https://evil.com" and acao == origin and acac.lower() == "true":
                results.append({{
                    "title": "CORS reflects arbitrary origin with credentials",
                    "description": f"Server reflects attacker origin ({{origin}}) with Allow-Credentials: true",
                    "severity": "critical",
                    "data": {{
                        "acao": acao,
                        "acac": acac,
                        "test_origin": origin
                    }}
                }})
            elif origin == "null" and acao == "null" and acac.lower() == "true":
                results.append({{
                    "title": "CORS allows null origin with credentials",
                    "description": "Server allows null origin with credentials — exploitable via sandboxed iframes",
                    "severity": "high",
                    "data": {{
                        "acao": acao,
                        "acac": acac,
                        "test_origin": origin
                    }}
                }})
        except Exception:
            pass

    # 4. Check for Referer header leaking session tokens
    test_paths = ["/", "/login", "/dashboard"]
    for path in test_paths:
        try:
            resp = client.get(base_url.rstrip("/") + path)
            # Check if URL contains session tokens
            final_url = str(resp.url)
            if any(kw in final_url.lower() for kw in ["session", "token", "sid="]):
                results.append({{
                    "title": f"Session token in URL — Referer header leakage risk",
                    "description": f"Session token in URL at {{path}} will leak via Referer header to external resources",
                    "severity": "high",
                    "data": {{
                        "path": path,
                        "url_contains_session": True
                    }}
                }})

            # Check Referrer-Policy header
            ref_policy = resp.headers.get("referrer-policy", "")
            if not ref_policy or ref_policy in ("unsafe-url", "no-referrer-when-downgrade"):
                results.append({{
                    "title": f"Weak or missing Referrer-Policy: {{path}}",
                    "description": f"Referrer-Policy is '{{ref_policy or 'not set'}}' — session tokens in URLs will leak via Referer",
                    "severity": "low",
                    "data": {{
                        "path": path,
                        "referrer_policy": ref_policy or "not set"
                    }}
                }})
                break  # Only report once
        except Exception:
            pass

    client.close()

    if not results:
        results.append({{
            "title": "Session hijacking test",
            "description": "No session hijacking vectors detected",
            "severity": "info",
            "data": {{}}
        }})

except Exception as e:
    results.append({{
        "title": "Session hijacking test error",
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
