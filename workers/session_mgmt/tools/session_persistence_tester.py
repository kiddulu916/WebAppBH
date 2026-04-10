"""Session cookie persistence testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class SessionPersistenceTester(SessionMgmtTool):
    """Test session cookie persistence behavior (WSTG-SESS-008)."""

    name = "session_persistence_tester"
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
    client = httpx.Client(verify=False, follow_redirects=True, timeout=10)

    # Step 1: Check for "remember me" functionality
    remember_me_found = False
    remember_me_paths = ["/login", "/auth/login", "/signin", "/wp-login.php", "/user/login"]
    remember_me_indicators = []

    for path in remember_me_paths:
        try:
            resp = client.get(base_url.rstrip("/") + path, timeout=10)
            body = resp.text

            # Check for remember me checkbox/field
            remember_patterns = [
                r'name=["\']remember[_-]?me["\']',
                r'name=["\']remember_me["\']',
                r'name=["\']persistent["\']',
                r'name=["\']stay[_-]?logged[_-]?in["\']',
                r'id=["\']remember[_-]?me["\']',
                r'for=["\']remember[_-]?me["\']',
                r'remember[_-]?me',
                r'stay[_-]?logged[_-]?in',
                r'keep[_-]?me[_-]?signed[_-]?in',
                r'keep[_-]?me[_-]?logged[_-]?in'
            ]

            for pattern in remember_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    remember_me_indicators.append(pattern)
                    remember_me_found = True
                    break
        except Exception:
            pass

    if remember_me_found:
        results.append({{
            "title": "Remember me functionality detected",
            "description": f"Found 'remember me' indicators on login pages. Persistent tokens should be analyzed for security.",
            "severity": "info",
            "data": {{
                "remember_me_detected": True,
                "indicators_found": remember_me_indicators[:5]
            }}
        }})

    # Step 2: Check for persistent session cookies (long-lived)
    persistent_cookies = []
    session_cookies = []

    # Check Set-Cookie headers for long expiration
    all_endpoints = ["/", "/login", "/dashboard", "/profile", "/settings"]
    for endpoint in all_endpoints:
        try:
            resp = client.get(base_url.rstrip("/") + endpoint, timeout=10)
            for header_name, header_value in resp.headers.multi_items():
                if header_name.lower() == "set-cookie":
                    cookie_name = header_value.split("=")[0].strip() if "=" in header_value else "unknown"
                    cookie_lower = header_value.lower()

                    is_session_cookie = any(kw in cookie_name.lower() for kw in [
                        "session", "sid", "token", "auth", "remember", "persistent"
                    ])

                    if is_session_cookie:
                        # Check for long expiration (> 30 days)
                        max_age = None
                        has_expires = False

                        if "max-age=" in cookie_lower:
                            try:
                                max_age = int(cookie_lower.split("max-age=")[1].split(";")[0].strip())
                            except (ValueError, IndexError):
                                pass

                        if "expires=" in cookie_lower:
                            has_expires = True

                        is_persistent = max_age is not None and max_age > 2592000  # 30 days
                        is_remember_cookie = "remember" in cookie_name.lower() or "persistent" in cookie_name.lower()

                        if is_persistent or is_remember_cookie:
                            persistent_cookies.append({{
                                "name": cookie_name,
                                "max_age": max_age,
                                "has_expires": has_expires,
                                "is_remember_cookie": is_remember_cookie
                            }})
                        else:
                            session_cookies.append({{
                                "name": cookie_name,
                                "max_age": max_age,
                                "has_expires": has_expires
                            }})
        except Exception:
            pass

    if persistent_cookies:
        for cookie in persistent_cookies:
            severity = "medium" if cookie.get("max_age") and cookie["max_age"] > 7776000 else "low"  # 90 days
            results.append({{
                "title": f"Persistent session cookie detected: {{cookie['name']}}",
                "description": f"The cookie '{{cookie['name']}}' has a long expiration time (max-age: {{cookie.get('max_age', 'N/A')}} seconds). Persistent tokens should be securely stored and rotated.",
                "severity": severity,
                "data": {{
                    "cookie_name": cookie["name"],
                    "max_age_seconds": cookie.get("max_age"),
                    "max_age_days": round(cookie.get("max_age", 0) / 86400, 1) if cookie.get("max_age") else None,
                    "is_remember_cookie": cookie.get("is_remember_cookie", False),
                    "recommendation": "Ensure persistent tokens are stored securely, rotated on use, and bound to user/device"
                }}
            }})

    # Step 3: Test remember me token rotation
    if persistent_cookies:
        for pcookie in persistent_cookies:
            cookie_name = pcookie["name"]
            try:
                # Get initial token
                resp = client.get(base_url, timeout=10)
                initial_token = resp.cookies.get(cookie_name)

                if initial_token:
                    # Make another request to see if token rotates
                    resp2 = client.get(base_url, timeout=10)
                    new_token = resp2.cookies.get(cookie_name)

                    if new_token and new_token != initial_token:
                        results.append({{
                            "title": f"Persistent token rotation detected for {{cookie_name}}",
                            "description": f"The persistent token '{{cookie_name}}' rotates on use, which is good security practice.",
                            "severity": "info",
                            "data": {{
                                "cookie_name": cookie_name,
                                "token_rotation": True
                            }}
                        }})
                    elif new_token and new_token == initial_token:
                        results.append({{
                            "title": f"Persistent token NOT rotating for {{cookie_name}}",
                            "description": f"The persistent token '{{cookie_name}}' does not rotate on use. Tokens should be rotated to prevent replay attacks.",
                            "severity": "medium",
                            "data": {{
                                "cookie_name": cookie_name,
                                "token_rotation": False,
                                "recommendation": "Implement token rotation for persistent session tokens"
                            }}
                        }})
            except Exception:
                pass

    # Step 4: Check for secure storage indicators
    try:
        resp = client.get(base_url, timeout=10)
        body_lower = resp.text.lower()

        secure_storage_patterns = [
            "token.binding",
            "device.fingerprint",
            "user.agent.validation",
            "ip.validation"
        ]
        found_patterns = [p for p in secure_storage_patterns if p.replace(".", "_") in body_lower or p.replace(".", " ") in body_lower]

        if found_patterns:
            results.append({{
                "title": "Persistent token binding indicators detected",
                "description": f"Found indicators of persistent token binding: {{found_patterns}}",
                "severity": "info",
                "data": {{
                    "binding_indicators": found_patterns
                }}
            }})
        else:
            results.append({{
                "title": "No persistent token binding detected",
                "description": "No indicators of persistent token binding to device or user-agent found. Persistent tokens may be usable from any client.",
                "severity": "low",
                "data": {{
                    "binding_detected": False,
                    "recommendation": "Bind persistent tokens to device fingerprint or user-agent"
                }}
            }})
    except Exception:
        pass

    if not results:
        results.append({{
            "title": "Session persistence test completed",
            "description": "No significant persistence-related issues detected. Manual testing recommended for comprehensive coverage.",
            "severity": "info",
            "data": {{
                "tests_performed": ["remember_me_detection", "persistent_cookie_analysis", "token_rotation_check", "binding_indicators"]
            }}
        }})

    client.close()

except Exception as e:
    results.append({{
        "title": "Session persistence test error",
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
