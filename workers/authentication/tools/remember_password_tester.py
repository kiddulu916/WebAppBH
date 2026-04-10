"""Remember password testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class RememberPasswordTester(AuthenticationTool):
    """Test remember password functionality (WSTG-ATHN-005)."""

    name = "remember_password_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        target_value = getattr(target, 'target_value', str(target))
        base_url = target_value if target_value.startswith(('http://', 'https://')) else f"https://{target_value}"

        script = f'''
import httpx
import json
import re
from urllib.parse import urljoin

results = []
base_url = "{base_url}"

def safe_get(url, **kwargs):
    try:
        return httpx.get(url, follow_redirects=True, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

def safe_post(url, **kwargs):
    try:
        return httpx.post(url, follow_redirects=False, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

# Discover login page
login_url = None
for path in ["/login", "/auth/login", "/signin", "/wp-login.php", "/admin/login", "/"]:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        if re.search(r'<form[^>]*>', r.text, re.IGNORECASE) or re.search(r'<input[^>]*type=["\\']?password', r.text, re.IGNORECASE):
            login_url = url
            break

if not login_url:
    login_url = urljoin(base_url, "/login")

# Fetch login page
r = safe_get(login_url)
if not r or r.status_code != 200:
    results.append({{
        "title": "Could not access login page",
        "description": f"Unable to access login page at {{login_url}} for remember password testing",
        "severity": "info",
        "data": {{"login_url": login_url, "status_code": r.status_code if r else None}}
    }})
    print(json.dumps(results))
    sys.exit(0)

html = r.text

# Test 1: Check for autocomplete="on" on password fields
password_fields = re.findall(r'<input[^>]*type=["\\']password["\\'][^>]*>', html, re.IGNORECASE)
for i, field in enumerate(password_fields):
    autocomplete_match = re.search(r'autocomplete=["\\']?([^"\\'\\s>]+)', field, re.IGNORECASE)
    if autocomplete_match:
        autocomplete_value = autocomplete_match.group(1).lower()
        if autocomplete_value == "on":
            results.append({{
                "title": "Password field has autocomplete enabled",
                "description": f"Password input field has autocomplete=\"on\". Browser may cache credentials in form history.",
                "severity": "medium",
                "data": {{"field_html": field[:200], "autocomplete_value": autocomplete_value}}
            }})
    else:
        # No autocomplete attribute means browser default (usually on)
        results.append({{
            "title": "Password field missing autocomplete attribute",
            "description": f"Password input field does not specify autocomplete attribute. Browser default behavior may cache credentials.",
            "severity": "low",
            "data": {{"field_html": field[:200]}}
        }})

# Test 2: Check for autocomplete on form element
form_autocomplete = re.search(r'<form[^>]*autocomplete=["\\']?([^"\\'\\s>]+)', html, re.IGNORECASE)
if form_autocomplete:
    form_auto_value = form_autocomplete.group(1).lower()
    if form_auto_value == "on":
        results.append({{
            "title": "Login form has autocomplete enabled",
            "description": "The login form element has autocomplete=\"on\". All form fields may be cached by the browser.",
            "severity": "medium",
            "data": {{"form_autocomplete": form_auto_value}}
        }})

# Test 3: Check for "Remember Me" functionality
remember_me_patterns = [
    r'<input[^>]*(?:name|id)=["\\']?remember["\\']?[^>]*>',
    r'<input[^>]*(?:name|id)=["\\']?remember[_-]?me["\\']?[^>]*>',
    r'<input[^>]*(?:name|id)=["\\']?persistent["\\']?[^>]*>',
    r'<input[^>]*(?:name|id)=["\\']?stay[_-]?logged[_-]?in["\\']?[^>]*>',
    r'<input[^>]*(?:name|id)=["\\']?keep[_-]?signed[_-]?in["\\']?[^>]*>',
    r'remember\\s*me',
    'stay logged in',
    'keep me signed in',
    'persistent login',
]

remember_me_found = False
for pattern in remember_me_patterns:
    if re.search(pattern, html, re.IGNORECASE):
        remember_me_found = True
        break

if remember_me_found:
    # Find the remember me checkbox/input
    remember_inputs = re.findall(r'<input[^>]*(?:name|id)=["\\']?(?:remember|remember[_-]?me|persistent|stay[_-]?logged[_-]?in|keep[_-]?signed[_-]?in)["\\']?[^>]*>', html, re.IGNORECASE)
    
    results.append({{
        "title": "Remember me functionality detected",
        "description": "Login page contains 'remember me' functionality. This may create persistent cookies that could be exploited if stolen.",
        "severity": "info",
        "data": {{
            "remember_me_inputs": [inp[:200] for inp in remember_inputs],
            "recommendation": "Verify persistent cookies have secure flags (HttpOnly, Secure, SameSite) and reasonable expiration"
        }}
    }})

# Test 4: Check for credentials in page source or JS variables
credential_patterns = [
    (r'(?:var|let|const)\\s+(?:password|passwd|pwd|credential)\\s*=\\s*["\\']([^"\\']+)["\\']', "hardcoded credential in JS"),
    (r'(?:password|passwd|pwd)\\s*[:=]\\s*["\\']([^"\\']{{4,}})["\\']', "potential credential in JS object"),
    (r'data-password=["\\']([^"\\']+)["\\']', "password in data attribute"),
]

for pattern, desc in credential_patterns:
    matches = re.findall(pattern, html, re.IGNORECASE)
    if matches:
        results.append({{
            "title": f"Potential {desc} found",
            "description": f"Found {{len(matches)}} occurrence(s) of {{desc}} in page source",
            "severity": "high",
            "data": {{"matches": matches[:5], "description": desc}}
        }})

# Test 5: Check for persistent session cookies after login attempt
if remember_me_found:
    # Try login with remember me checked
    remember_input = re.search(r'<input[^>]*(?:name|id)=["\\']?([^"\\'>\\s]*)["\\']?[^>]*(?:remember|persistent)', html, re.IGNORECASE)
    if remember_input:
        remember_name = remember_input.group(1)
        
        # Get form action URL
        form_action = re.search(r'<form[^>]*action=["\\']([^"\\']*)["\\']', html, re.IGNORECASE)
        action_url = urljoin(login_url, form_action.group(1)) if form_action else login_url
        
        # Get form method
        form_method = re.search(r'<form[^>]*method=["\\']?([^"\\'\\s>]+)', html, re.IGNORECASE)
        method = (form_method.group(1).lower() if form_method else "post")
        
        # Extract other form fields
        form_fields = {{}}
        for field in re.findall(r'<input[^>]*(?:name)=["\\']([^"\\']+)["\\'][^>]*(?:value)=["\\']([^"\\']*)["\\']', html, re.IGNORECASE):
            if field[0] not in ['username', 'password', 'remember', 'remember_me']:
                form_fields[field[0]] = field[1]
        
        # Attempt login with remember me
        login_data = {{
            "username": "test_user_nonexistent",
            "password": "test_password_wrong",
            remember_name: "on"
        }}
        login_data.update(form_fields)
        
        r = safe_post(action_url, data=login_data)
        if r:
            # Check for persistent cookies
            for cookie in r.cookies:
                cookie_attrs = {{}}
                # Check cookie attributes from Set-Cookie header
                set_cookie_headers = r.headers.get_list("set-cookie")
                for header in set_cookie_headers:
                    if cookie.name in header:
                        cookie_attrs["httponly"] = "httponly" in header.lower()
                        cookie_attrs["secure"] = "secure" in header.lower()
                        cookie_attrs["samesite"] = re.search(r'samesite=(\\w+)', header, re.IGNORECASE)
                        cookie_attrs["samesite"] = cookie_attrs["samesite"].group(1) if cookie_attrs["samesite"] else None
                        cookie_attrs["max-age"] = re.search(r'max-age=(\\d+)', header, re.IGNORECASE)
                        cookie_attrs["max-age"] = int(cookie_attrs["max-age"].group(1)) if cookie_attrs["max-age"] else None
                        cookie_attrs["expires"] = re.search(r'expires=([^;]+)', header, re.IGNORECASE)
                        cookie_attrs["expires"] = cookie_attrs["expires"].group(1) if cookie_attrs["expires"] else None
                
                # Check for long-lived cookies (persistent)
                is_persistent = False
                if cookie_attrs.get("max-age") and cookie_attrs["max-age"] > 86400:  # > 1 day
                    is_persistent = True
                if cookie_attrs.get("expires"):
                    is_persistent = True
                if "remember" in cookie.name.lower() or "persistent" in cookie.name.lower():
                    is_persistent = True
                
                if is_persistent:
                    issues = []
                    if not cookie_attrs.get("httponly"):
                        issues.append("missing HttpOnly flag")
                    if not cookie_attrs.get("secure"):
                        issues.append("missing Secure flag")
                    if not cookie_attrs.get("samesite") or cookie_attrs["samesite"].lower() == "none":
                        issues.append("missing or weak SameSite attribute")
                    
                    if issues:
                        results.append({{
                            "title": f"Persistent cookie '{{cookie.name}}' has security weaknesses",
                            "description": f"Remember me cookie '{{cookie.name}}' has: {{', '.join(issues)}}",
                            "severity": "medium",
                            "data": {{
                                "cookie_name": cookie.name,
                                "issues": issues,
                                "cookie_attrs": cookie_attrs
                            }}
                        }})

# Test 6: Check for password cached in browser storage patterns
storage_patterns = [
    r'localStorage\\.(?:setItem|getItem)\\s*\\(\\s*["\\'](?:password|credential|token)',
    r'sessionStorage\\.(?:setItem|getItem)\\s*\\(\\s*["\\'](?:password|credential)',
    r'window\\.(?:localStorage|sessionStorage)',
]

for pattern in storage_patterns:
    if re.search(pattern, html, re.IGNORECASE):
        results.append({{
            "title": "Browser storage access detected on login page",
            "description": "Login page accesses browser localStorage/sessionStorage. Credentials or tokens may be stored insecurely.",
            "severity": "medium",
            "data": {{"pattern": pattern}}
        }})

# Summary
if not results:
    results.append({{
        "title": "Remember password checks completed",
        "description": "No significant remember password weaknesses detected",
        "severity": "info",
        "data": {{"login_url": login_url}}
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
