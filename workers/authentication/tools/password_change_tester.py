"""Password change testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class PasswordChangeTester(AuthenticationTool):
    """Test password change functionality (WSTG-ATHN-009)."""

    name = "password_change_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_value = getattr(target, 'target_value', str(target))
        base_url = target_value if target_value.startswith(('http://', 'https://')) else f"https://{target_value}"

        script = f'''
import httpx
import json
import re
import time
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

def safe_put(url, **kwargs):
    try:
        return httpx.put(url, follow_redirects=False, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

# Discover password change page
password_change_urls = []
for path in [
    "/settings/password", "/account/password", "/profile/password",
    "/change-password", "/password/change", "/settings/security",
    "/account/security", "/user/password", "/my-account/password",
    "/api/password", "/api/v1/password", "/api/v1/user/password",
]:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        password_change_urls.append(url)

# Test 1: Check if password change requires current password
for pc_url in password_change_urls:
    r = safe_get(pc_url)
    if not r or r.status_code != 200:
        continue
    
    html = r.text
    
    # Look for current password field
    has_current_password = bool(re.search(
        r'<input[^>]*(?:name|id)=["\\']?(?:current[_-]?password|old[_-]?password|existing[_-]?password)["\\']?',
        html, re.IGNORECASE
    ))
    
    # Also check for text hints
    has_current_password_text = bool(re.search(
        r'(?:current|old|existing)\\s*password',
        html, re.IGNORECASE
    ))
    
    if not has_current_password and not has_current_password_text:
        results.append({{
            "title": f"Password change may not require current password at {{pc_url}}",
            "description": f"The password change form at {{pc_url}} does not appear to require the current password. This could allow account takeover if session is hijacked.",
            "severity": "high",
            "data": {{
                "url": pc_url,
                "has_current_password_field": has_current_password,
                "has_current_password_text": has_current_password_text
            }}
        }})
    else:
        results.append({{
            "title": "Password change requires current password",
            "description": f"Password change form at {{pc_url}} requires current password verification.",
            "severity": "info",
            "data": {{"url": pc_url}}
        }})

# Test 2: Test CSRF on password change
for pc_url in password_change_urls:
    r = safe_get(pc_url)
    if not r:
        continue
    
    html = r.text
    
    # Find form action
    form_action = re.search(r'<form[^>]*action=["\\']([^"\\']*)["\\']', html, re.IGNORECASE)
    action_url = urljoin(pc_url, form_action.group(1)) if form_action else pc_url
    
    # Find CSRF token
    csrf_token = None
    csrf_patterns = [
        r'<input[^>]*name=["\\']?(?:_token|csrf_token|csrf|authenticity_token|xsrftoken|csrfmiddlewaretoken)["\\']?[^>]*value=["\\']([^"\\']+)["\\']',
        r'<meta[^>]*name=["\\']?(?:csrf-token|csrf_token)["\\']?[^>]*content=["\\']([^"\\']+)["\\']',
    ]
    for pattern in csrf_patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            csrf_token = match.group(1)
            break
    
    # Try password change without CSRF token
    form_data = {{
        "current_password": "test_current",
        "new_password": "NewSecurePass123!",
        "confirm_password": "NewSecurePass123!",
    }}
    
    r = safe_post(action_url, data=form_data)
    if r:
        # Check if request succeeded without CSRF
        if r.status_code in (200, 201, 302, 301):
            text = r.text.lower() if r.text else ""
            if not any(x in text for x in ["csrf", "token", "invalid", "forbidden", "error"]):
                if not csrf_token:
                    results.append({{
                        "title": f"Password change may be vulnerable to CSRF at {{action_url}}",
                        "description": f"Password change request succeeded without CSRF token at {{action_url}}",
                        "severity": "high",
                        "data": {{
                            "url": action_url,
                            "csrf_token_present": bool(csrf_token),
                            "status_code": r.status_code
                        }}
                    }})

# Test 3: Test password change with incorrect current password
for pc_url in password_change_urls:
    r = safe_get(pc_url)
    if not r:
        continue
    
    html = r.text
    form_action = re.search(r'<form[^>]*action=["\\']([^"\\']*)["\\']', html, re.IGNORECASE)
    action_url = urljoin(pc_url, form_action.group(1)) if form_action else pc_url
    
    # Try with wrong current password
    form_data = {{
        "current_password": "wrong_current_password_xyz",
        "new_password": "NewSecurePass123!",
        "confirm_password": "NewSecurePass123!",
    }}
    
    r = safe_post(action_url, data=form_data)
    if r:
        text = r.text.lower() if r.text else ""
        
        # Check if wrong current password was accepted
        if r.status_code in (200, 201, 302, 301):
            if not any(x in text for x in ["incorrect", "invalid", "wrong", "error", "failed", "current password"]):
                results.append({{
                    "title": f"Password change accepted incorrect current password at {{action_url}}",
                    "description": f"Password change succeeded with incorrect current password at {{action_url}}",
                    "severity": "critical",
                    "data": {{
                        "url": action_url,
                        "status_code": r.status_code
                    }}
                }})
        elif r.status_code == 400 or r.status_code == 422:
            if "current" in text or "password" in text:
                results.append({{
                    "title": "Password change validates current password",
                    "description": f"Password change correctly rejects incorrect current password",
                    "severity": "info",
                    "data": {{"url": action_url}}
                }})

# Test 4: Test password confirmation bypass
for pc_url in password_change_urls:
    r = safe_get(pc_url)
    if not r:
        continue
    
    html = r.text
    form_action = re.search(r'<form[^>]*action=["\\']([^"\\']*)["\\']', html, re.IGNORECASE)
    action_url = urljoin(pc_url, form_action.group(1)) if form_action else pc_url
    
    # Try without confirm_password field
    form_data_no_confirm = {{
        "current_password": "test_current",
        "new_password": "NewSecurePass123!",
    }}
    
    r = safe_post(action_url, data=form_data_no_confirm)
    if r and r.status_code in (200, 201, 302, 301):
        text = r.text.lower() if r.text else ""
        if not any(x in text for x in ["confirm", "match", "error", "invalid"]):
            results.append({{
                "title": f"Password confirmation may be bypassable at {{action_url}}",
                "description": f"Password change succeeded without confirm_password field at {{action_url}}",
                "severity": "medium",
                "data": {{"url": action_url, "status_code": r.status_code}}
            }})

# Test 5: Test password change via HTTP method manipulation
for pc_url in password_change_urls:
    # Try PUT instead of POST
    form_data = {{
        "current_password": "test_current",
        "new_password": "NewSecurePass123!",
        "confirm_password": "NewSecurePass123!",
    }}
    
    r = safe_put(pc_url, data=form_data)
    if r and r.status_code not in (405, 501, 404):
        text = r.text.lower() if r.text else ""
        if not any(x in text for x in ["error", "invalid", "not allowed", "method"]):
            results.append({{
                "title": f"Password change accessible via PUT method at {{pc_url}}",
                "description": f"Password change endpoint accepts PUT requests, which may bypass CSRF protections",
                "severity": "medium",
                "data": {{"url": pc_url, "method": "PUT", "status_code": r.status_code}}
            }})

# Test 6: Check for password change via API endpoints
api_paths = [
    "/api/password", "/api/v1/password", "/api/v2/password",
    "/api/user/password", "/api/account/password",
    "/api/settings/password", "/api/v1/user/password",
]

for api_path in api_paths:
    url = urljoin(base_url, api_path)
    
    # Try without authentication
    r = safe_post(url, json={{
        "current_password": "test",
        "new_password": "NewPass123!",
    }})
    
    if r and r.status_code not in (401, 403):
        results.append({{
            "title": f"Password change API accessible without authentication: {{api_path}}",
            "description": f"Password change endpoint {{api_path}} returned status {{r.status_code}} without authentication",
            "severity": "critical",
            "data": {{"url": url, "status_code": r.status_code}}
        }})

# Summary
results.append({{
    "title": "Password change test summary",
    "description": f"Tested {{len(password_change_urls)}} password change pages",
    "severity": "info",
    "data": {{
        "password_change_urls": password_change_urls,
        "api_paths_tested": len(api_paths)
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
