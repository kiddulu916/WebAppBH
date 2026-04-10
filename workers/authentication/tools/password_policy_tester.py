"""Password policy testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class PasswordPolicyTester(AuthenticationTool):
    """Test password policy strength (WSTG-ATHN-007)."""

    name = "password_policy_tester"
    weight_class = WeightClass.HEAVY

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

def safe_post(url, **kwargs):
    try:
        return httpx.post(url, follow_redirects=False, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

def safe_get(url, **kwargs):
    try:
        return httpx.get(url, follow_redirects=True, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

# Discover registration and password change pages
register_url = None
password_change_url = None

for path in ["/register", "/signup", "/account/register", "/auth/register", "/user/register", "/create-account"]:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        if re.search(r'<form[^>]*>', r.text, re.IGNORECASE):
            register_url = url
            break

for path in ["/settings/password", "/account/password", "/profile/password", "/change-password", "/password/change", "/settings/security"]:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        if re.search(r'<form[^>]*>', r.text, re.IGNORECASE):
            password_change_url = url
            break

# Test passwords to try
test_passwords = [
    ("password", "very common password"),
    ("123456", "numeric only"),
    ("12345678", "numeric only 8 chars"),
    ("qwerty", "keyboard pattern"),
    ("abc123", "simple alphanumeric"),
    ("monkey", "common dictionary word"),
    ("master", "common dictionary word"),
    ("dragon", "common dictionary word"),
    ("111111", "single repeated digit"),
    ("baseball", "common dictionary word"),
    ("iloveyou", "common phrase"),
    ("trustno1", "common leetspeak"),
    ("sunshine", "common dictionary word"),
    ("letmein", "common phrase"),
    ("admin", "default admin password"),
    ("welcome", "common dictionary word"),
    ("password1", "common password with number"),
    ("Password1", "common password with capital"),
    ("P@ssw0rd", "common leetspeak password"),
    ("test", "short test password"),
    ("a", "single character"),
    ("ab", "two characters"),
    ("abc", "three characters"),
    ("abcd", "four characters"),
    ("abcde", "five characters"),
    ("abcdef", "six characters"),
    ("abcdefg", "seven characters"),
    ("abcdefgh", "eight characters"),
]

# Test 1: Analyze registration page for password policy hints
if register_url:
    r = safe_get(register_url)
    if r and r.status_code == 200:
        html = r.text
        
        # Look for password policy text
        policy_patterns = [
            r'(?:must|should|required|minimum|at least)\\s+(?:be\\s+)?(?:at\\s+least\\s+)?(\\d+)\\s+(?:characters|chars)',
            r'(?:minimum|min)\\s+(?:length|size)\\s*(?::|is)?\\s*(\\d+)',
            r'(?:password|pwd)\\s*(?:length|size)\\s*(?::|is)?\\s*(\\d+)',
            r'minlength=["\\']?(\\d+)["\\']?',
            r'maxlength=["\\']?(\\d+)["\\']?',
        ]
        
        for pattern in policy_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                results.append({{
                    "title": "Password policy hint found on registration page",
                    "description": f"Found password policy hint matching pattern: {{pattern}}. Values: {{matches}}",
                    "severity": "info",
                    "data": {{
                        "pattern": pattern,
                        "values": matches,
                        "page": register_url
                    }}
                }})
        
        # Check for password strength meter
        if re.search(r'(?:strength|meter|entropy|zxcvbn)', html, re.IGNORECASE):
            results.append({{
                "title": "Password strength meter detected",
                "description": "Registration page appears to have a password strength meter, which is a good practice.",
                "severity": "info",
                "data": {{"page": register_url}}
            }})
        
        # Check for password requirements list
        requirements = []
        if re.search(r'(?:uppercase|capital|A-Z)', html, re.IGNORECASE):
            requirements.append("uppercase")
        if re.search(r'(?:lowercase|small|a-z)', html, re.IGNORECASE):
            requirements.append("lowercase")
        if re.search(r'(?:digit|number|0-9|numeric)', html, re.IGNORECASE):
            requirements.append("digit")
        if re.search(r'(?:special|symbol|[^a-zA-Z0-9])', html, re.IGNORECASE):
            requirements.append("special character")
        
        if requirements:
            results.append({{
                "title": "Password complexity requirements detected",
                "description": f"Registration page indicates password must contain: {{', '.join(requirements)}}",
                "severity": "info",
                "data": {{
                    "requirements": requirements,
                    "page": register_url
                }}
            }})

# Test 2: Test weak passwords on registration
if register_url:
    # Get form details
    r = safe_get(register_url)
    if r and r.status_code == 200:
        html = r.text
        
        # Find form action
        form_action = re.search(r'<form[^>]*action=["\\']([^"\\']*)["\\']', html, re.IGNORECASE)
        action_url = urljoin(register_url, form_action.group(1)) if form_action else register_url
        
        # Find form fields
        form_fields = {{}}
        for field in re.findall(r'<input[^>]*name=["\\']([^"\\']+)["\\'][^>]*(?:value=["\\']([^"\\']*)["\\'])?', html, re.IGNORECASE):
            name, value = field
            if name not in ['username', 'email', 'password', 'password_confirm', 'confirm_password']:
                form_fields[name] = value or ""
        
        # Find password field names
        password_fields = re.findall(r'<input[^>]*type=["\\']password["\\'][^>]*name=["\\']([^"\\']+)["\\']', html, re.IGNORECASE)
        password_field = password_fields[0] if password_fields else "password"
        
        # Find username/email field names
        username_fields = re.findall(r'<input[^>]*type=["\\']?(?:text|email)["\\']?[^>]*name=["\\']([^"\\']+)["\\']', html, re.IGNORECASE)
        username_field = username_fields[0] if username_fields else "username"
        
        # Test weak passwords
        weak_passwords_accepted = []
        for pwd, desc in test_passwords:
            # Generate unique username for each attempt
            import time
            test_user = f"testuser_{{int(time.time()*1000)}}"
            test_email = f"{{test_user}}@test.com"
            
            form_data = {{
                username_field: test_user,
                "email": test_email,
                password_field: pwd,
            }}
            form_data.update(form_fields)
            
            # Add password confirmation if there are two password fields
            if len(password_fields) > 1:
                form_data[password_fields[1]] = pwd
            
            r = safe_post(action_url, data=form_data)
            if r:
                text = r.text.lower() if r.text else ""
                
                # Check if registration succeeded
                success_indicators = ["welcome", "registration successful", "account created", "verify your email", "check your email", "thank you for registering"]
                error_indicators = ["password", "weak", "too short", "invalid", "error", "not allowed", "must contain", "requires", "complexity"]
                
                success_count = sum(1 for x in success_indicators if x in text)
                error_count = sum(1 for x in error_indicators if x in text)
                
                # Check for redirect to success page
                if r.status_code in (301, 302, 303):
                    location = r.headers.get("location", "").lower()
                    if any(x in location for x in ["welcome", "verify", "success", "login"]):
                        if not any(x in location for x in ["error", "fail"]):
                            weak_passwords_accepted.append({{"password": pwd, "description": desc, "status_code": r.status_code}})
                            continue
                
                if success_count > error_count and success_count >= 1:
                    weak_passwords_accepted.append({{"password": pwd, "description": desc, "status_code": r.status_code}})
                elif error_count == 0 and r.status_code == 200:
                    # No error message and status 200 - might have succeeded
                    if len(r.text) > 100:  # Substantial response
                        weak_passwords_accepted.append({{"password": pwd, "description": desc, "status_code": r.status_code, "note": "no error returned"}})
        
        if weak_passwords_accepted:
            severity = "critical" if len(weak_passwords_accepted) > 5 else "high"
            results.append({{
                "title": f"{{len(weak_passwords_accepted)}} weak passwords accepted during registration",
                "description": f"The registration form accepted {{len(weak_passwords_accepted)}} weak passwords, indicating insufficient password policy enforcement.",
                "severity": severity,
                "data": {{
                    "weak_passwords": weak_passwords_accepted[:10],
                    "total_accepted": len(weak_passwords_accepted),
                    "total_tested": len(test_passwords)
                }}
            }})
        else:
            results.append({{
                "title": "Weak passwords rejected during registration",
                "description": f"All {{len(test_passwords)}} weak passwords were rejected during registration, indicating good password policy enforcement.",
                "severity": "info",
                "data": {{"passwords_tested": len(test_passwords)}}
            }})

# Test 3: Test password change with weak passwords
if password_change_url:
    r = safe_get(password_change_url)
    if r and r.status_code == 200:
        html = r.text
        
        form_action = re.search(r'<form[^>]*action=["\\']([^"\\']*)["\\']', html, re.IGNORECASE)
        action_url = urljoin(password_change_url, form_action.group(1)) if form_action else password_change_url
        
        # Test if password change accepts weak passwords
        # Note: This requires authentication, so we can only test the form response
        form_data = {{
            "current_password": "any_password",
            "new_password": "password",
            "confirm_password": "password",
        }}
        
        r = safe_post(action_url, data=form_data)
        if r:
            text = r.text.lower() if r.text else ""
            
            # Check if weak password was rejected
            if "weak" in text or "too short" in text or "complexity" in text or "not allowed" in text:
                results.append({{
                    "title": "Password change enforces complexity",
                    "description": "Password change form appears to enforce password complexity requirements.",
                    "severity": "info",
                    "data": {{"page": password_change_url}}
                }})
            elif r.status_code in (401, 403):
                results.append({{
                    "title": "Password change requires authentication",
                    "description": "Password change endpoint correctly requires authentication.",
                    "severity": "info",
                    "data": {{"page": password_change_url, "status_code": r.status_code}}
                }})

# Test 4: Check for password reuse policies
if register_url or password_change_url:
    page_url = register_url or password_change_url
    r = safe_get(page_url)
    if r:
        text = r.text.lower() if r.text else ""
        
        if re.search(r'(?:password\\s*history|reuse|previous\\s*password|old\\s*password)', text):
            results.append({{
                "title": "Password reuse policy detected",
                "description": "Application appears to enforce password history/reuse policy.",
                "severity": "info",
                "data": {{"page": page_url}}
            }})
        else:
            results.append({{
                "title": "No password reuse policy detected",
                "description": "No indication of password history or reuse policy enforcement.",
                "severity": "low",
                "data": {{"page": page_url}}
            }})

# Summary
results.append({{
    "title": "Password policy test summary",
    "description": f"Tested password policy on registration and password change pages",
    "severity": "info",
    "data": {{
        "register_url": register_url,
        "password_change_url": password_change_url,
        "test_passwords_count": len(test_passwords)
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
