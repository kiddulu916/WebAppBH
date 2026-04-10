"""Authentication bypass testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class AuthBypassTester(AuthenticationTool):
    """Test for authentication bypass vulnerabilities (WSTG-ATHN-004)."""

    name = "auth_bypass_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_value = getattr(target, 'target_value', str(target))
        base_url = target_value if target_value.startswith(('http://', 'https://')) else f"https://{target_value}"

        script = f'''
import httpx
import json
import sys
import re
from urllib.parse import urljoin, urlparse

results = []
base_url = "{base_url}"

def safe_request(method, url, **kwargs):
    try:
        client = httpx.Client(verify=False, follow_redirects=False, timeout=10)
        func = getattr(client, method.lower())
        return func(url, **kwargs)
    except Exception:
        return None

def safe_get(url, **kwargs):
    return safe_request("GET", url, **kwargs)

def safe_post(url, **kwargs):
    return safe_request("POST", url, **kwargs)

def safe_put(url, **kwargs):
    return safe_request("PUT", url, **kwargs)

def safe_delete(url, **kwargs):
    return safe_request("DELETE", url, **kwargs)

def safe_patch(url, **kwargs):
    return safe_request("PATCH", url, **kwargs)

def is_protected(response):
    """Check if response indicates authentication is required."""
    if response is None:
        return True
    if response.status_code in (302, 301, 303, 307, 308):
        location = response.headers.get("location", "").lower()
        if any(x in location for x in ["login", "auth", "signin", "unauthorized"]):
            return True
    if response.status_code in (401, 403):
        return True
    text = response.text.lower() if response.text else ""
    if any(x in text for x in ["login required", "please log in", "sign in to continue", "unauthorized", "access denied", "authentication required"]):
        return True
    return False

def discover_protected_paths():
    """Discover potentially protected paths."""
    paths = [
        "/admin", "/admin/dashboard", "/admin/users", "/admin/settings",
        "/api/users", "/api/admin", "/api/config", "/api/settings",
        "/dashboard", "/profile", "/account", "/settings",
        "/console", "/manager", "/control-panel", "/portal",
        "/api/v1/users", "/api/v1/admin", "/api/v2/users",
        "/internal", "/debug", "/status", "/health",
        "/wp-admin", "/wp-json/wp/v2/users",
        "/phpmyadmin", "/pma", "/database",
        "/.env", "/config.json", "/config.yml",
        "/backup", "/backups", "/dump",
        "/server-status", "/server-info",
    ]
    
    protected = []
    for path in paths:
        url = urljoin(base_url, path)
        r = safe_get(url)
        if r and not is_protected(r):
            protected.append({{"path": path, "status_code": r.status_code, "accessible": True}})
        elif r:
            protected.append({{"path": path, "status_code": r.status_code, "accessible": False}})
    return protected

# Test 1: Direct access to authenticated pages without login
paths = discover_protected_paths()
accessible_paths = [p for p in paths if p.get("accessible")]

if accessible_paths:
    for p in accessible_paths:
        results.append({{
            "title": f"Protected page accessible without authentication: {{p['path']}}",
            "description": f"The path {{p['path']}} returned status {{p['status_code']}} without requiring authentication",
            "severity": "high",
            "data": {{"path": p["path"], "status_code": p["status_code"]}}
        }})
else:
    results.append({{
        "title": "All tested paths require authentication",
        "description": "All common protected paths returned authentication-required responses",
        "severity": "info",
        "data": {{"paths_tested": len(paths)}}
    }})

# Test 2: HTTP method bypass - try PUT/DELETE/PATCH on auth-required endpoints
for path_data in paths:
    path = path_data["path"]
    url = urljoin(base_url, path)
    
    for method_name, method_func in [("PUT", safe_put), ("DELETE", safe_delete), ("PATCH", safe_patch)]:
        r = method_func(url)
        if r and not is_protected(r) and r.status_code not in (405, 501):
            results.append({{
                "title": f"Authentication bypass via {{method_name}} method: {{path}}",
                "description": f"Using {{method_name}} method on {{path}} returned status {{r.status_code}}, bypassing authentication",
                "severity": "high",
                "data": {{
                    "path": path,
                    "method": method_name,
                    "status_code": r.status_code,
                    "response_length": len(r.text) if r.text else 0
                }}
            }})

# Test 3: Path traversal to bypass auth
traversal_paths = [
    "/admin/../../admin",
    "/login/../admin",
    "/static/../../admin",
    "/public/../admin",
    "/%2e%2e/%2e%2e/admin",
    "/..;/admin",
    "/admin/..;/",
    "/./admin/./",
    "/admin%00",
    "/admin/",
    "/admin//",
    "/admin/.",
]

for path in traversal_paths:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and not is_protected(r) and r.status_code not in (400, 404):
        results.append({{
            "title": f"Authentication bypass via path traversal: {{path}}",
            "description": f"Path traversal sequence '{{path}}' returned status {{r.status_code}}, potentially bypassing authentication",
            "severity": "high",
            "data": {{
                "path": path,
                "status_code": r.status_code,
                "response_length": len(r.text) if r.text else 0
            }}
        }})

# Test 4: Header injection bypass
headers_to_test = [
    {{"X-Original-URL": "/admin"}},
    {{"X-Rewrite-URL": "/admin"}},
    {{"X-Forwarded-For": "127.0.0.1"}},
    {{"X-Forwarded-Host": "localhost"}},
    {{"X-Host": "localhost"}},
    {{"X-Forwarded-Server": "localhost"}},
    {{"X-Custom-IP-Authorization": "127.0.0.1"}},
]

for headers in headers_to_test:
    url = urljoin(base_url, "/")
    r = safe_get(url, headers=headers)
    if r and not is_protected(r) and r.status_code not in (400, 404):
        header_str = ", ".join(f"{{k}}: {{v}}" for k, v in headers.items())
        results.append({{
            "title": f"Authentication bypass via header injection: {{header_str}}",
            "description": f"Adding headers '{{header_str}}' returned status {{r.status_code}}, potentially bypassing authentication",
            "severity": "high",
            "data": {{
                "headers": headers,
                "status_code": r.status_code,
                "response_length": len(r.text) if r.text else 0
            }}
        }})

# Test 5: Cookie manipulation
cookie_tests = [
    {{"admin": "true"}},
    {{"admin": "1"}},
    {{"is_admin": "true"}},
    {{"role": "admin"}},
    {{"role": "administrator"}},
    {{"user_type": "admin"}},
    {{"authenticated": "true"}},
    {{"isAuthenticated": "true"}},
    {{"access": "granted"}},
    {{"user": "admin"}},
]

for cookies in cookie_tests:
    url = urljoin(base_url, "/admin")
    r = safe_get(url, cookies=cookies)
    if r and not is_protected(r) and r.status_code not in (404,):
        results.append({{
            "title": f"Authentication bypass via cookie manipulation: {{list(cookies.keys())[0]}}={{list(cookies.values())[0]}}",
            "description": f"Setting cookie '{{list(cookies.keys())[0]}}={{list(cookies.values())[0]}}' returned status {{r.status_code}} on /admin",
            "severity": "high",
            "data": {{
                "cookies": cookies,
                "target_path": "/admin",
                "status_code": r.status_code
            }}
        }})

# Test 6: JWT none algorithm bypass (if JWT is detected)
# First check if the app uses JWT
r = safe_get(urljoin(base_url, "/"))
if r:
    set_cookie = r.headers.get("set-cookie", "")
    auth_header_pattern = None
    
    # Check for JWT in cookies
    jwt_in_cookie = re.search(r'(?:token|jwt|auth|session)=([a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+)', set_cookie)
    
    if jwt_in_cookie:
        original_jwt = jwt_in_cookie.group(1)
        # Try none algorithm
        import base64
        
        def decode_jwt_part(part):
            try:
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += '=' * padding
                return base64.urlsafe_b64decode(part)
            except Exception:
                return b'{{}}'
        
        try:
            header = json.loads(decode_jwt_part(original_jwt.split('.')[0]))
            payload = decode_jwt_part(original_jwt.split('.')[1])
            
            # Create none algorithm JWT
            none_header = base64.urlsafe_b64encode(json.dumps({{"alg": "none", "typ": "JWT"}}).encode()).rstrip(b'=').decode()
            none_jwt = f"{{none_header}}.{{original_jwt.split('.')[1]}}."
            
            # Test with none algorithm JWT
            none_cookies = {{"token": none_jwt}}
            r_none = safe_get(urljoin(base_url, "/admin"), cookies=none_cookies)
            if r_none and not is_protected(r_none):
                results.append({{
                    "title": "JWT none algorithm bypass successful",
                    "description": "JWT with 'none' algorithm was accepted, bypassing authentication",
                    "severity": "critical",
                    "data": {{
                        "original_jwt_header": header,
                        "none_jwt": none_jwt[:50] + "..."
                    }}
                }})
        except Exception:
            pass

# Summary
results.append({{
    "title": "Authentication bypass test summary",
    "description": f"Tested {{len(paths)}} paths for direct access, {{len(traversal_paths)}} traversal paths, {{len(headers_to_test)}} header injections, {{len(cookie_tests)}} cookie manipulations",
    "severity": "info",
    "data": {{
        "paths_tested": len(paths),
        "accessible_without_auth": len(accessible_paths),
        "traversal_tests": len(traversal_paths),
        "header_tests": len(headers_to_test),
        "cookie_tests": len(cookie_tests)
    }}
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
