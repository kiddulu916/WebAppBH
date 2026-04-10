"""Default credential testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class DefaultCredentialTester(AuthenticationTool):
    """Test for default credentials (WSTG-ATHN-002)."""

    name = "default_credential_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_value = getattr(target, 'target_value', str(target))
        base_url = target_value if target_value.startswith(('http://', 'https://')) else f"https://{target_value}"

        script = f'''
import httpx
import json
import sys
import asyncio
from urllib.parse import urljoin, urlparse

results = []
base_url = "{base_url}"

# Common default credential combinations
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("test", "test"),
    ("user", "user"),
    ("user", "password"),
    ("administrator", "administrator"),
    ("administrator", "admin"),
    ("administrator", "password"),
    ("guest", "guest"),
    ("guest", "password"),
    ("demo", "demo"),
    ("demo", "password"),
    ("support", "support"),
    ("support", "password"),
    ("operator", "operator"),
    ("sysadmin", "sysadmin"),
    ("webadmin", "webadmin"),
    ("manager", "manager"),
]

# Common login paths to test
LOGIN_PATHS = [
    "/login",
    "/admin",
    "/admin/login",
    "/admin/index.php",
    "/wp-login.php",
    "/administrator",
    "/auth",
    "/auth/login",
    "/signin",
    "/sign-in",
    "/user/login",
    "/accounts/login",
    "/account/login",
    "/login.php",
    "/login.aspx",
    "/login.html",
    "/j_security_check",
    "/manager/html",
    "/console",
    "/api/login",
    "/api/auth",
    "/api/v1/login",
    "/api/v1/auth",
    "/rest/login",
    "/sso/login",
    "/portal/login",
    "/dashboard/login",
    "/control",
    "/panel",
    "/cpanel",
    "/webmail",
    "/phpmyadmin",
    "/pma",
]

def safe_post(url, data=None, json_data=None, headers=None, timeout=10):
    try:
        return httpx.post(url, data=data, json=json_data, headers=headers or {{}}, timeout=timeout, follow_redirects=False, verify=False)
    except Exception:
        return None

def safe_get(url, timeout=10):
    try:
        return httpx.get(url, timeout=timeout, follow_redirects=False, verify=False)
    except Exception:
        return None

def is_successful_login(response, original_response=None):
    """Heuristic to detect successful login."""
    if response is None:
        return False
    
    # Check for redirect to dashboard/admin area
    if response.status_code in (301, 302, 303, 307, 308):
        location = response.headers.get("location", "").lower()
        if any(x in location for x in ["dashboard", "admin", "home", "welcome", "portal", "console"]):
            if not any(x in location for x in ["login", "error", "fail", "invalid"]):
                return True
    
    # Check response for success indicators
    text = response.text.lower() if response.text else ""
    
    # Success indicators
    success_indicators = ["welcome", "dashboard", "logout", "sign out", "my account", "profile", "admin panel"]
    # Failure indicators
    failure_indicators = ["invalid", "incorrect", "failed", "error", "wrong", "unauthorized", "forbidden", "denied"]
    
    success_count = sum(1 for x in success_indicators if x in text)
    failure_count = sum(1 for x in failure_indicators if x in text)
    
    # Check for session cookies
    has_session_cookie = any("session" in c.name.lower() or "token" in c.name.lower() for c in response.cookies)
    
    if has_session_cookie and failure_count == 0:
        return True
    
    if success_count > failure_count and success_count >= 2:
        return True
    
    # Check if response is significantly different from failed login
    if original_response and response.text:
        if len(response.text) != len(original_response.text):
            # Different response size might indicate different behavior
            pass
    
    return False

def get_failed_login_response(login_url):
    """Get a baseline failed login response for comparison."""
    return safe_post(login_url, data={{"username": "nonexistent_user_xyz", "password": "wrong_password_xyz"}})

# Test each login path with default credentials
tested_paths = []
successful_logins = []

for path in LOGIN_PATHS:
    login_url = urljoin(base_url, path)
    
    # First check if the path exists
    r = safe_get(login_url, timeout=5)
    if r is None or r.status_code in (404, 403, 401):
        # Path might still accept POST even if GET returns 404
        if r and r.status_code == 404:
            continue
    
    tested_paths.append(path)
    
    # Get baseline failed response
    failed_response = get_failed_login_response(login_url)
    
    for username, password in DEFAULT_CREDS:
        # Try form-based login
        form_data = {{"username": username, "password": password}}
        r = safe_post(login_url, data=form_data)
        
        if r and is_successful_login(r, failed_response):
            successful_logins.append({{
                "path": path,
                "username": username,
                "password": password,
                "status_code": r.status_code,
            }})
            results.append({{
                "title": f"Default credentials accepted: {{username}}/{{password}}",
                "description": f"Default credentials were accepted at {{login_url}}. Username: {{username}}, Password: {{password}}",
                "severity": "critical",
                "data": {{
                    "login_url": login_url,
                    "username": username,
                    "password": password,
                    "status_code": r.status_code,
                    "response_headers": dict(r.headers),
                    "cookies": {{c.name: c.value for c in r.cookies}}
                }}
            }})
            break  # Found working creds, move to next path
        
        # Try JSON-based login
        json_data = {{"username": username, "password": password}}
        headers = {{"Content-Type": "application/json"}}
        r = safe_post(login_url, json=json_data, headers=headers)
        
        if r and is_successful_login(r, failed_response):
            successful_logins.append({{
                "path": path,
                "username": username,
                "password": password,
                "status_code": r.status_code,
            }})
            results.append({{
                "title": f"Default credentials accepted (JSON): {{username}}/{{password}}",
                "description": f"Default credentials were accepted at {{login_url}} via JSON API. Username: {{username}}, Password: {{password}}",
                "severity": "critical",
                "data": {{
                    "login_url": login_url,
                    "username": username,
                    "password": password,
                    "auth_type": "json",
                    "status_code": r.status_code
                }}
            }})
            break  # Found working creds, move to next path

# Also test with provided credentials if available
provided_creds = {credentials}
if provided_creds:
    login_url = provided_creds.get("login_url", urljoin(base_url, "/login"))
    username = provided_creds.get("username", "admin")
    password = provided_creds.get("password", "admin")
    
    r = safe_post(login_url, data={{"username": username, "password": password}})
    if r and is_successful_login(r):
        results.append({{
            "title": f"Provided default credentials accepted: {{username}}/{{password}}",
            "description": f"Provided credentials were accepted at {{login_url}}",
            "severity": "critical",
            "data": {{
                "login_url": login_url,
                "username": username,
                "password": password
            }}
        }})

# Summary
if not results:
    results.append({{
        "title": "No default credentials found",
        "description": f"Tested {{len(DEFAULT_CREDS)}} default credential combinations against {{len(tested_paths)}} login paths. No successful logins detected.",
        "severity": "info",
        "data": {{
            "tested_paths": tested_paths[:10],
            "paths_count": len(tested_paths),
            "credential_combos_tested": len(DEFAULT_CREDS)
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
