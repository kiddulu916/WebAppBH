"""Cookie attribute testing tool (Secure, HttpOnly, SameSite)."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class CookieAttributeTester(SessionMgmtTool):
    """Test session cookie security attributes (WSTG-SESS-003)."""

    name = "cookie_attribute_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json

results = []
base_url = "{base_url}"

try:
    client = httpx.Client(verify=False, follow_redirects=True, timeout=10)

    # Collect all Set-Cookie headers from multiple endpoints
    cookie_headers = []
    endpoints_to_check = ["/", "/login", "/auth/login", "/api/login", "/signin", "/dashboard", "/profile"]

    for endpoint in endpoints_to_check:
        try:
            url = base_url.rstrip("/") + endpoint
            resp = client.get(url)
            for header_name, header_value in resp.headers.multi_items():
                if header_name.lower() == "set-cookie":
                    cookie_headers.append(header_value)
        except Exception:
            pass

    # Also try POST to login endpoints
    login_paths = ["/login", "/auth/login", "/api/login", "/signin"]
    for path in login_paths:
        try:
            resp = client.post(
                base_url.rstrip("/") + path,
                data={{"username": "test", "password": "test"}},
                timeout=10
            )
            for header_name, header_value in resp.headers.multi_items():
                if header_name.lower() == "set-cookie":
                    cookie_headers.append(header_value)
        except Exception:
            pass

    if not cookie_headers:
        results.append({{
            "title": "No Set-Cookie headers found",
            "description": "No session cookies were set during testing. The application may use alternative authentication mechanisms.",
            "severity": "info",
            "data": {{"endpoints_checked": endpoints_to_check + login_paths}}
        }})
    else:
        for cookie_header in cookie_headers:
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=")[0].strip() if "=" in cookie_header else "unknown"

            # Only analyze session-related cookies
            is_session_cookie = any(kw in cookie_name.lower() for kw in [
                "session", "sid", "token", "auth", "jsessionid", "phpsessid",
                "asp.net", "connect.sid", "remember", "csrf", "xsrf"
            ])

            if not is_session_cookie:
                continue

            findings = []

            # Check Secure flag
            has_secure = "; secure" in cookie_lower
            if not has_secure:
                findings.append({{
                    "title": f"Session cookie '{{cookie_name}}' missing Secure flag",
                    "description": f"The cookie '{{cookie_name}}' does not have the Secure attribute set. This means the cookie will be sent over unencrypted HTTP connections, potentially exposing session tokens to interception.",
                    "severity": "high",
                    "data": {{
                        "cookie_name": cookie_name,
                        "attribute": "Secure",
                        "present": False,
                        "recommendation": "Set the Secure flag on all session cookies to ensure they are only transmitted over HTTPS"
                    }}
                }})

            # Check HttpOnly flag
            has_httponly = "httponly" in cookie_lower
            if not has_httponly:
                findings.append({{
                    "title": f"Session cookie '{{cookie_name}}' missing HttpOnly flag",
                    "description": f"The cookie '{{cookie_name}}' does not have the HttpOnly attribute set. This means the cookie is accessible via JavaScript, increasing the risk of session theft through XSS attacks.",
                    "severity": "medium",
                    "data": {{
                        "cookie_name": cookie_name,
                        "attribute": "HttpOnly",
                        "present": False,
                        "recommendation": "Set the HttpOnly flag on session cookies to prevent JavaScript access"
                    }}
                }})

            # Check SameSite attribute
            samesite_value = None
            if "samesite=strict" in cookie_lower:
                samesite_value = "Strict"
            elif "samesite=lax" in cookie_lower:
                samesite_value = "Lax"
            elif "samesite=none" in cookie_lower:
                samesite_value = "None"

            if samesite_value is None:
                findings.append({{
                    "title": f"Session cookie '{{cookie_name}}' missing SameSite attribute",
                    "description": f"The cookie '{{cookie_name}}' does not have the SameSite attribute set. Without this attribute, the cookie is sent with cross-site requests, potentially enabling CSRF attacks.",
                    "severity": "medium",
                    "data": {{
                        "cookie_name": cookie_name,
                        "attribute": "SameSite",
                        "present": False,
                        "recommendation": "Set SameSite=Strict or SameSite=Lax on session cookies to mitigate CSRF"
                    }}
                }})
            elif samesite_value == "None":
                findings.append({{
                    "title": f"Session cookie '{{cookie_name}}' has SameSite=None",
                    "description": f"The cookie '{{cookie_name}}' has SameSite=None, which means it is sent with all cross-site requests. This provides no CSRF protection.",
                    "severity": "low",
                    "data": {{
                        "cookie_name": cookie_name,
                        "attribute": "SameSite",
                        "value": "None",
                        "recommendation": "Consider using SameSite=Lax or SameSite=Strict for better CSRF protection"
                    }}
                }})

            # Check Domain attribute
            has_domain = "domain=" in cookie_lower
            if has_domain:
                try:
                    domain_val = cookie_lower.split("domain=")[1].split(";")[0].strip()
                    if domain_val.startswith("."):
                        findings.append({{
                            "title": f"Session cookie '{{cookie_name}}' has broad Domain scope",
                            "description": f"The cookie '{{cookie_name}}' has Domain={{domain_val}}, which includes all subdomains. This increases the attack surface if any subdomain is compromised.",
                            "severity": "low",
                            "data": {{
                                "cookie_name": cookie_name,
                                "attribute": "Domain",
                                "value": domain_val,
                                "recommendation": "Restrict Domain attribute to the specific domain if subdomain access is not required"
                            }}
                        }})
                except (IndexError, ValueError):
                    pass

            # Check Path attribute
            has_path = "path=" in cookie_lower
            if not has_path:
                findings.append({{
                    "title": f"Session cookie '{{cookie_name}}' missing Path attribute",
                    "description": f"The cookie '{{cookie_name}}' does not have a Path attribute set. It defaults to the current path, which may be broader than necessary.",
                    "severity": "info",
                    "data": {{
                        "cookie_name": cookie_name,
                        "attribute": "Path",
                        "present": False
                    }}
                }})

            # Check for Max-Age/Expires
            has_max_age = "max-age=" in cookie_lower
            has_expires = "expires=" in cookie_lower
            if not has_max_age and not has_expires:
                findings.append({{
                    "title": f"Session cookie '{{cookie_name}}' has no expiration",
                    "description": f"The cookie '{{cookie_name}}' does not have Max-Age or Expires set. It will persist until the browser is closed.",
                    "severity": "info",
                    "data": {{
                        "cookie_name": cookie_name,
                        "has_max_age": has_max_age,
                        "has_expires": has_expires
                    }}
                }})

            if not findings:
                findings.append({{
                    "title": f"Session cookie '{{cookie_name}}' has secure attributes",
                    "description": f"The cookie '{{cookie_name}}' has all recommended security attributes (Secure, HttpOnly, SameSite).",
                    "severity": "info",
                    "data": {{
                        "cookie_name": cookie_name,
                        "secure": has_secure,
                        "httponly": has_httponly,
                        "samesite": samesite_value,
                        "has_domain": has_domain,
                        "has_path": has_path
                    }}
                }})

            results.extend(findings)

    client.close()

except Exception as e:
    results.append({{
        "title": "Cookie attribute test error",
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
