"""Client-side authentication testing tool (WSTG-CLIENT-010)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class ClientAuthTester(ClientSideTool):
    """Test for client-side authentication vulnerabilities (WSTG-CLIENT-010).

    Checks for authentication state in localStorage, JWT token handling,
    authentication bypass vectors, and session management issues.
    """

    name = "client_auth_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import re
import base64

results = []
base_url = "{base_url}"

headers = {{}}
if credentials and credentials.get("token"):
    headers["Authorization"] = f"Bearer {{credentials.get('token')}}"

try:
    client = httpx.Client(follow_redirects=True, timeout=15, verify=False)

    resp = client.get(base_url, headers=headers)
    content = resp.text

    # Check for authentication state stored in localStorage
    auth_storage_patterns = [
        (r'localStorage\\.setItem\\s*\\(\\s*["\\']([^"\\'>]*(?:token|auth|session|jwt|user|login|credential)[^"\\'>]*)["\\']', 'Auth state in localStorage'),
        (r'sessionStorage\\.setItem\\s*\\(\\s*["\\']([^"\\'>]*(?:token|auth|session|jwt|user|login|credential)[^"\\'>]*)["\\']', 'Auth state in sessionStorage'),
    ]

    for pattern, desc in auth_storage_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            results.append({{
                "title": f"{{desc}}",
                "description": f"Found {{len(matches)}} authentication-related storage key(s) in client-side code at {base_url}",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "keys": matches[:10],
                    "storage_type": "localStorage" if "localStorage" in pattern else "sessionStorage"
                }}
            }})

    # Check for JWT tokens in client-side storage
    jwt_patterns = [
        r'["\\']?(?:eyJ[a-zA-Z0-9_-]+\\.eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+)["\\']?',
        r'jwt\\s*[:=]\\s*["\\']eyJ',
        r'token\\s*[:=]\\s*["\\']eyJ',
        r'Bearer\\s+eyJ',
    ]

    jwt_found = False
    for pattern in jwt_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            jwt_found = True
            break

    if jwt_found:
        results.append({{
            "title": "JWT token found in client-side code",
            "description": f"JWT token pattern detected in client-side code at {base_url}. Tokens should not be hardcoded.",
            "severity": "high",
            "data": {{
                "url": base_url,
                "issue": "JWT token in client-side code"
            }}
        }})

    # Check for JWT algorithm confusion (none algorithm)
    if re.search(r'["\\']none["\\'].*algorithm|algorithm.*["\\']none["\\']', content, re.IGNORECASE):
        results.append({{
            "title": "JWT 'none' algorithm reference",
            "description": f"Found reference to JWT 'none' algorithm at {base_url}. This could indicate algorithm confusion vulnerability.",
            "severity": "high",
            "data": {{
                "url": base_url,
                "issue": "JWT none algorithm"
            }}
        }})

    # Check for authentication bypass via client-side manipulation
    bypass_patterns = [
        (r'isAuthenticated\\s*=\\s*true', 'Client-side auth state manipulation'),
        (r'isLoggedIn\\s*=\\s*true', 'Client-side login state manipulation'),
        (r'hasAccess\\s*=\\s*true', 'Client-side access state manipulation'),
        (r'role\\s*[:=]\\s*["\\']admin["\\']', 'Client-side role manipulation'),
        (r'isAdmin\\s*=\\s*true', 'Client-side admin flag manipulation'),
        (r'authenticated\\s*:\\s*true', 'Client-side authenticated flag'),
        (r'if\\s*\\(\\s*!.*auth', 'Negative auth check (potential bypass)'),
    ]

    for pattern, desc in bypass_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({{
                "title": f"Authentication bypass vector: {{desc}}",
                "description": f"Found {{desc}} in client-side code at {base_url}. Authentication state should be validated server-side.",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }}
            }})

    # Check for proper token validation
    validation_patterns = [
        (r'jwt\\.verify|verifyToken|validateToken', 'Token validation present'),
        (r'expir|exp\\s*:', 'Token expiration check'),
        (r'iss\\s*[:=]', 'Token issuer check'),
        (r'aud\\s*[:=]', 'Token audience check'),
    ]

    has_validation = any(re.search(p, content, re.IGNORECASE) for p, _ in validation_patterns[:1])
    has_expiry = any(re.search(p, content, re.IGNORECASE) for p, _ in validation_patterns[1:2])
    has_issuer = any(re.search(p, content, re.IGNORECASE) for p, _ in validation_patterns[2:3])
    has_audience = any(re.search(p, content, re.IGNORECASE) for p, _ in validation_patterns[3:4])

    if not has_validation and re.search(r'(?:token|jwt|auth)', content, re.IGNORECASE):
        results.append({{
            "title": "Missing token validation",
            "description": f"Authentication tokens are used at {base_url} but no token validation logic was found in client-side code",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "has_validation": has_validation,
                "has_expiry_check": has_expiry,
                "has_issuer_check": has_issuer,
                "has_audience_check": has_audience
            }}
        }})

    # Check for session fixation via client-side storage
    fixation_patterns = [
        r'sessionId\\s*[:=]',
        r'session_id\\s*[:=]',
        r'PHPSESSID',
        r'JSESSIONID',
        r'ASP\\.NET_SessionId',
    ]

    for pattern in fixation_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({{
                "title": "Session ID handling in client-side code",
                "description": f"Found session ID reference at {base_url}. Session IDs should not be manipulated client-side.",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "pattern": pattern
                }}
            }})
            break

    # Check for OAuth state parameter validation
    oauth_patterns = [
        r'oauth|OAuth',
        r'state\\s*[:=]',
        r'authorization_code',
        r'implicit\\s*(?:grant|flow)',
        r'pkce|code_verifier|code_challenge',
    ]

    has_oauth = any(re.search(p, content, re.IGNORECASE) for p in oauth_patterns)
    if has_oauth:
        has_state_validation = bool(re.search(r'state\\s*===|state\\s*==|validateState|verifyState', content, re.IGNORECASE))
        if not has_state_validation:
            results.append({{
                "title": "Missing OAuth state parameter validation",
                "description": f"OAuth flow detected at {base_url} but no state parameter validation found. This is vulnerable to CSRF attacks.",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "has_state_validation": has_state_validation
                }}
            }})

        # Check for implicit flow (deprecated)
        if re.search(r'implicit', content, re.IGNORECASE):
            results.append({{
                "title": "OAuth implicit flow usage",
                "description": f"OAuth implicit flow detected at {base_url}. This flow is deprecated and less secure than authorization code flow with PKCE.",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "flow_type": "implicit"
                }}
            }})

    # Check for cookie security attributes
    set_cookies = resp.headers.get_list("set-cookie")
    for cookie in set_cookies:
        issues = []
        if "secure" not in cookie.lower():
            issues.append("missing Secure flag")
        if "httponly" not in cookie.lower():
            issues.append("missing HttpOnly flag")
        if "samesite" not in cookie.lower():
            issues.append("missing SameSite attribute")

        if issues:
            cookie_name = cookie.split("=")[0].split(";")[0].strip()
            if any(auth_term in cookie_name.lower() for auth_term in ['session', 'token', 'auth', 'jwt', 'sid']):
                results.append({{
                    "title": f"Insecure cookie attributes for '{{cookie_name}}'",
                    "description": f"Authentication-related cookie '{{cookie_name}}' at {base_url} has: {{', '.join(issues)}}",
                    "severity": "high",
                    "data": {{
                        "url": base_url,
                        "cookie_name": cookie_name,
                        "issues": issues
                    }}
                }})

    client.close()

except Exception as e:
    results.append({{
        "title": "Client authentication test error",
        "description": str(e),
        "severity": "info",
        "data": {{"error": str(e)}}
    }})

print(json.dumps(results))
'''
        return ["python3", "-c", script]

    def parse_output(self, stdout: str) -> list:
        import json
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
