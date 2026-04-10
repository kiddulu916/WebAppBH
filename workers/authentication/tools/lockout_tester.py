"""Lockout mechanism testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class LockoutTester(AuthenticationTool):
    """Test account lockout mechanisms (WSTG-ATHN-003)."""

    name = "lockout_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_value = getattr(target, 'target_value', str(target))
        base_url = target_value if target_value.startswith(('http://', 'https://')) else f"https://{target_value}"
        
        cred_username = credentials.get("username", "testuser") if credentials else "testuser"
        cred_login_url = credentials.get("login_url", "") if credentials else ""

        script = f'''
import httpx
import json
import sys
import time
from urllib.parse import urljoin

results = []
base_url = "{base_url}"
test_username = "{cred_username}"
login_url = "{cred_login_url}" or urljoin(base_url, "/login")

MAX_ATTEMPTS = 15
LOCKOUT_THRESHOLD = 5

def safe_post(url, data=None, json_data=None, headers=None, timeout=10):
    try:
        return httpx.post(url, data=data, json=json_data, headers=headers or {{}}, timeout=timeout, follow_redirects=False, verify=False)
    except Exception as e:
        return None

def safe_get(url, timeout=10):
    try:
        return httpx.get(url, timeout=timeout, follow_redirects=False, verify=False)
    except Exception:
        return None

# Discover login URL if not provided
if not login_url or login_url == urljoin(base_url, "/login"):
    for path in ["/login", "/auth/login", "/signin", "/wp-login.php", "/admin/login"]:
        r = safe_get(urljoin(base_url, path), timeout=5)
        if r and r.status_code == 200:
            login_url = urljoin(base_url, path)
            break

# Phase 1: Attempt multiple failed logins and track responses
responses = []
lockout_detected = False
lockout_at_attempt = None
error_messages = set()

for attempt in range(1, MAX_ATTEMPTS + 1):
    # Try form-based login
    r = safe_post(login_url, data={{"username": test_username, "password": f"wrong_password_{{attempt}}"}})
    
    if r is None:
        responses.append({{"attempt": attempt, "status": "error", "status_code": None}})
        continue
    
    status_code = r.status_code
    response_text = r.text.lower() if r.text else ""
    
    # Extract error messages from response
    error_msg = ""
    for indicator in ["invalid", "incorrect", "failed", "locked", "too many", "exceeded", "blocked", "disabled", "attempts", "try again", "wait"]:
        if indicator in response_text:
            # Try to extract the actual message
            import re
            patterns = [
                r'<[^>]*class="[^"]*(?:error|alert|message|warning)[^"]*"[^>]*>([^<]+)</[^>]+>',
                r'<div[^>]*>([^<]*(?:{{}})[^<]*)</div>'.format(indicator),
            ]
            error_msg = indicator
            break
    
    error_messages.add(error_msg)
    
    resp_info = {{
        "attempt": attempt,
        "status_code": status_code,
        "response_length": len(r.text) if r.text else 0,
        "error_message": error_msg,
        "headers": dict(r.headers)
    }}
    responses.append(resp_info)
    
    # Detect lockout indicators
    if status_code == 429:
        lockout_detected = True
        lockout_at_attempt = attempt
        break
    
    if status_code == 403:
        if "lock" in response_text or "blocked" in response_text or "too many" in response_text:
            lockout_detected = True
            lockout_at_attempt = attempt
            break
    
    # Check for lockout message in response
    if any(x in response_text for x in ["account locked", "account locked", "too many attempts", "try again later", "temporarily locked", "locked out"]):
        lockout_detected = True
        lockout_at_attempt = attempt
        break
    
    # Check if response changes significantly (potential lockout)
    if attempt > 3 and responses:
        first_resp_length = responses[0].get("response_length", 0)
        current_length = resp_info.get("response_length", 0)
        if first_resp_length > 0 and abs(current_length - first_resp_length) / first_resp_length > 0.5:
            # Significant change in response - might be lockout
            if any(x in response_text for x in ["lock", "block", "wait", "cool", "later"]):
                lockout_detected = True
                lockout_at_attempt = attempt
                break

# Phase 2: Analyze results
if lockout_detected:
    results.append({{
        "title": f"Account lockout detected after {{lockout_at_attempt}} attempts",
        "description": f"Account '{{test_username}}' was locked after {{lockout_at_attempt}} failed login attempts. This indicates lockout mechanism is in place.",
        "severity": "info",
        "data": {{
            "username": test_username,
            "lockout_at_attempt": lockout_at_attempt,
            "total_attempts": len(responses),
            "lockout_type": "automatic"
        }}
    }})
else:
    results.append({{
        "title": f"No account lockout after {{MAX_ATTEMPTS}} failed attempts",
        "description": f"Account '{{test_username}}' was NOT locked after {{MAX_ATTEMPTS}} failed login attempts. This may indicate missing or weak lockout protection, enabling brute-force attacks.",
        "severity": "medium",
        "data": {{
            "username": test_username,
            "attempts_made": MAX_ATTEMPTS,
            "lockout_detected": False
        }}
    }})

# Phase 3: Check for user enumeration via lockout messages
# Try with a non-existent user and compare error messages
nonexistent_user = "nonexistent_user_xyz_12345"
r_nonexistent = safe_post(login_url, data={{"username": nonexistent_user, "password": "wrong_password"}})

if r_nonexistent and responses:
    nonexistent_text = r_nonexistent.text.lower() if r_nonexistent.text else ""
    
    # Get error message for valid user (first failed attempt)
    valid_user_error = ""
    if responses:
        r_valid = safe_post(login_url, data={{"username": test_username, "password": "wrong_password_first"}})
        if r_valid:
            valid_user_text = r_valid.text.lower() if r_valid.text else ""
            
            # Check if error messages differ
            if nonexistent_text != valid_user_text:
                results.append({{
                    "title": "User enumeration via error message difference",
                    "description": f"Different error messages returned for valid vs invalid usernames. This allows attackers to enumerate valid usernames.",
                    "severity": "medium",
                    "data": {{
                        "valid_user_response_length": len(r_valid.text) if r_valid.text else 0,
                        "invalid_user_response_length": len(r_nonexistent.text) if r_nonexistent.text else 0,
                        "responses_differ": True
                    }}
                }})

# Phase 4: Check if locked account can still be enumerated
if lockout_detected:
    # Try login with locked account - check response
    r_locked = safe_post(login_url, data={{"username": test_username, "password": "any_password"}})
    if r_locked:
        locked_text = r_locked.text.lower() if r_locked.text else ""
        
        # Try with wrong password for non-existent user
        r_other = safe_post(login_url, data={{"username": "totally_random_user_xyz", "password": "wrong"}})
        if r_other:
            other_text = r_other.text.lower() if r_other.text else ""
            
            if locked_text != other_text:
                results.append({{
                    "title": "Locked account can be enumerated",
                    "description": "Response for locked account differs from non-existent account response, allowing enumeration of locked accounts.",
                    "severity": "low",
                    "data": {{
                        "locked_response_differs": True
                    }}
                }})

# Phase 5: Check for rate limiting headers
for resp in responses:
    headers = resp.get("headers", {{}})
    rate_limit_headers = ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after"]
    found_headers = [h for h in rate_limit_headers if h in headers]
    
    if found_headers:
        results.append({{
            "title": "Rate limiting headers present",
            "description": f"Rate limiting headers detected: {{', '.join(found_headers)}}",
            "severity": "info",
            "data": {{
                "headers": {{h: headers.get(h) for h in found_headers}}
            }}
        }})
        break

# Summary
results.append({{
    "title": "Lockout test summary",
    "description": f"Performed {{MAX_ATTEMPTS}} failed login attempts for user '{{test_username}}'. Lockout: {{'Yes' if lockout_detected else 'No'}} at attempt {{lockout_at_attempt or 'N/A'}}.",
    "severity": "info",
    "data": {{
        "target": base_url,
        "login_url": login_url,
        "max_attempts": MAX_ATTEMPTS,
        "lockout_detected": lockout_detected,
        "lockout_at_attempt": lockout_at_attempt,
        "unique_error_messages": len(error_messages)
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
