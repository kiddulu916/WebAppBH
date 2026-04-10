"""Multi-channel authentication testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class MultiChannelAuthTester(AuthenticationTool):
    """Test multi-channel authentication mechanisms (WSTG-ATHN-010)."""

    name = "multi_channel_auth_tester"
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

# Discover MFA/2FA related endpoints
mfa_endpoints = []
for path in [
    "/mfa", "/2fa", "/two-factor", "/two_factor",
    "/otp", "/totp", "/verify", "/verify-code",
    "/mfa/setup", "/2fa/setup", "/otp/verify",
    "/api/mfa", "/api/2fa", "/api/v1/mfa",
    "/api/v1/otp", "/api/v1/verify",
    "/account/mfa", "/account/2fa", "/settings/mfa",
    "/security/mfa", "/security/2fa",
]:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        mfa_endpoints.append(url)

# Also check for MFA indicators in login flow
login_url = None
for path in ["/login", "/auth/login", "/signin"]:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        if re.search(r'<form[^>]*>', r.text, re.IGNORECASE):
            login_url = url
            break

if not login_url:
    login_url = urljoin(base_url, "/login")

# Test 1: Check if MFA is enforced
mfa_enforced = False
mfa_indicators = []

for url in mfa_endpoints:
    r = safe_get(url)
    if r:
        text = r.text.lower() if r.text else ""
        if any(x in text for x in ["two-factor", "two factor", "mfa", "multi-factor", "otp", "verification code", "authenticator"]):
            mfa_indicators.append(url)

# Check login page for MFA references
r = safe_get(login_url)
if r:
    text = r.text.lower() if r.text else ""
    if any(x in text for x in ["two-factor", "two factor", "mfa", "multi-factor", "otp"]):
        mfa_indicators.append(login_url)

if mfa_indicators:
    results.append({{
        "title": "MFA/2FA functionality detected",
        "description": f"Found {{len(mfa_indicators)}} endpoints related to multi-factor authentication",
        "severity": "info",
        "data": {{
            "mfa_endpoints": mfa_endpoints,
            "mfa_indicators": mfa_indicators
        }}
    }})
else:
    results.append({{
        "title": "No MFA/2FA functionality detected",
        "description": "No multi-factor authentication endpoints or indicators found. Consider implementing MFA for sensitive operations.",
        "severity": "medium",
        "data": {{"endpoints_checked": len(mfa_endpoints) + 1}}
    }})

# Test 2: Test MFA bypass by manipulating response
# Try accessing MFA-protected endpoints without completing MFA
mfa_protected_paths = [
    "/dashboard", "/admin", "/settings", "/account",
    "/api/users", "/api/admin", "/profile",
]

for path in mfa_protected_paths:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        text = r.text.lower() if r.text else ""
        # Check if page is accessible without MFA
        if not any(x in text for x in ["verify", "otp", "code", "mfa", "two-factor"]):
            results.append({{
                "title": f"Potentially MFA-bypassable endpoint: {{path}}",
                "description": f"Endpoint {{path}} returned 200 without MFA verification prompt",
                "severity": "medium",
                "data": {{"path": path, "status_code": r.status_code}}
            }})

# Test 3: Test MFA code brute-forcing
for mfa_url in mfa_endpoints:
    if "verify" in mfa_url.lower() or "otp" in mfa_url.lower():
        # Try multiple MFA codes
        codes_tried = 0
        rate_limited = False
        
        for i in range(20):
            code = f"{{i:06d}}"  # 6-digit codes
            form_data = {{
                "code": code,
                "otp": code,
                "token": code,
                "verification_code": code,
            }}
            
            r = safe_post(mfa_url, data=form_data)
            if r:
                codes_tried += 1
                if r.status_code == 429:
                    rate_limited = True
                    break
                if "too many" in r.text.lower() or "rate limit" in r.text.lower():
                    rate_limited = True
                    break
                if "invalid" in r.text.lower() or "incorrect" in r.text.lower():
                    continue  # Expected response
        
        if not rate_limited and codes_tried >= 10:
            results.append({{
                "title": f"MFA codes can be brute-forced at {{mfa_url}}",
                "description": f"No rate limiting detected on MFA verification endpoint. Successfully submitted {{codes_tried}} codes without throttling.",
                "severity": "high",
                "data": {{
                    "url": mfa_url,
                    "codes_submitted": codes_tried,
                    "rate_limiting": False
                }}
            }})
        elif rate_limited:
            results.append({{
                "title": "Rate limiting on MFA verification",
                "description": f"Rate limiting detected after {{codes_tried}} attempts on MFA endpoint",
                "severity": "info",
                "data": {{
                    "url": mfa_url,
                    "attempts_before_limit": codes_tried
                }}
            }})

# Test 4: Test MFA code reuse
# Try using the same MFA code multiple times
for mfa_url in mfa_endpoints:
    if "verify" in mfa_url.lower() or "otp" in mfa_url.lower():
        test_code = "123456"
        
        # First attempt
        r1 = safe_post(mfa_url, data={{"code": test_code}})
        # Second attempt with same code
        r2 = safe_post(mfa_url, data={{"code": test_code}})
        
        if r1 and r2:
            if r1.status_code == r2.status_code and r1.text == r2.text:
                results.append({{
                    "title": f"MFA code reuse possible at {{mfa_url}}",
                    "description": "Same MFA code produces identical responses on multiple attempts. Code may be reusable.",
                    "severity": "medium",
                    "data": {{
                        "url": mfa_url,
                        "first_status": r1.status_code,
                        "second_status": r2.status_code
                    }}
                }})

# Test 5: Test if MFA is enforced on sensitive operations
sensitive_operations = [
    ("PUT", "/api/user/email", {{"email": "attacker@evil.com"}}),
    ("PUT", "/api/user/password", {{"password": "NewPass123!"}}),
    ("POST", "/api/user/delete", {{}}),
    ("PUT", "/api/account/settings", {{"settings": "modified"}}),
    ("POST", "/api/transfer", {{"amount": 100, "to": "attacker"}}),
]

for method, path, data in sensitive_operations:
    url = urljoin(base_url, path)
    
    # Try without MFA
    client = httpx.Client(verify=False, follow_redirects=False, timeout=10)
    try:
        if method == "PUT":
            r = client.put(url, json=data)
        else:
            r = client.post(url, json=data)
        
        if r.status_code not in (401, 403):
            results.append({{
                "title": f"Sensitive operation {{method}} {{path}} may not require MFA",
                "description": f"{{method}} request to {{path}} returned status {{r.status_code}} without MFA verification",
                "severity": "high",
                "data": {{
                    "method": method,
                    "path": path,
                    "status_code": r.status_code
                }}
            }})
    except Exception:
        pass
    finally:
        client.close()

# Test 6: Check for backup codes
backup_code_paths = [
    "/mfa/backup-codes", "/2fa/backup-codes",
    "/api/mfa/backup", "/api/2fa/backup",
    "/account/backup-codes", "/settings/backup-codes",
]

for path in backup_code_paths:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        text = r.text.lower() if r.text else ""
        if "backup" in text and "code" in text:
            results.append({{
                "title": f"Backup codes endpoint found: {{path}}",
                "description": f"Backup codes endpoint accessible at {{path}}. Verify backup codes are secure.",
                "severity": "info",
                "data": {{"url": url}}
            }})
            
            # Test if backup codes can be brute-forced
            for i in range(10):
                test_code = f"BACKUP-{{i:04d}}"
                r = safe_post(url, data={{"backup_code": test_code}})
                if r and r.status_code == 429:
                    results.append({{
                        "title": "Backup code brute-forcing rate limited",
                        "description": "Backup code endpoint has rate limiting against brute-force",
                        "severity": "info",
                        "data": {{"url": url}}
                    }})
                    break

# Test 7: Check MFA setup security
for mfa_url in mfa_endpoints:
    if "setup" in mfa_url.lower():
        r = safe_get(mfa_url)
        if r and r.status_code == 200:
            text = r.text.lower() if r.text else ""
            
            # Check for insecure MFA setup
            if "skip" in text and ("mfa" in text or "2fa" in text or "two" in text):
                results.append({{
                    "title": f"MFA setup can be skipped at {{mfa_url}}",
                    "description": "MFA setup page contains option to skip MFA configuration",
                    "severity": "medium",
                    "data": {{"url": mfa_url}}
                }})
            
            # Check if MFA secret is exposed in page
            if re.search(r'secret["\\']?\\s*[:=]\\s*["\\']?[A-Z2-7]{{16,}}', text):
                results.append({{
                    "title": "MFA secret potentially exposed in page source",
                    "description": f"MFA setup page at {{mfa_url}} may expose the TOTP secret in page source",
                    "severity": "high",
                    "data": {{"url": mfa_url}}
                }})

# Summary
results.append({{
    "title": "Multi-channel authentication test summary",
    "description": f"Tested MFA enforcement, brute-force protection, code reuse, and sensitive operation protection",
    "severity": "info",
    "data": {{
        "mfa_endpoints_found": len(mfa_endpoints),
        "mfa_indicators_found": len(mfa_indicators),
        "sensitive_operations_tested": len(sensitive_operations)
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
