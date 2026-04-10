"""Registration process testing tool (WSTG-IDENT-002)."""

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.concurrency import WeightClass


class RegistrationTester(IdentityMgmtTool):
    """Test user registration processes (WSTG-IDENT-002)."""

    name = "registration_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import sys
import re

results = []
base_url = "{base_url}"

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    # Discover registration endpoints
    reg_endpoints = [
        "/register", "/signup", "/api/register", "/api/signup",
        "/auth/register", "/auth/signup", "/api/v1/register", "/api/v1/signup",
        "/user/register", "/user/signup", "/api/user/register",
        "/account/create", "/api/account/create",
    ]

    found_reg_endpoints = []
    for ep in reg_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            resp = client.get(url)
            if resp.status_code == 200:
                found_reg_endpoints.append(ep)
                # Check for CAPTCHA presence
                captcha_patterns = [
                    r'g-recaptcha', r'h-captcha', r'cf-turnstile',
                    r'recaptcha', r'hcaptcha', r'turnstile',
                    r'captcha', r'human verification'
                ]
                has_captcha = any(re.search(p, resp.text, re.IGNORECASE) for p in captcha_patterns)
                if not has_captcha:
                    results.append({{
                        "title": "Registration endpoint without CAPTCHA",
                        "description": f"Registration endpoint {{ep}} does not appear to have CAPTCHA protection",
                        "severity": "medium",
                        "data": {{
                            "endpoint": ep,
                            "status_code": resp.status_code
                        }}
                    }})
        except Exception:
            pass

    # Test email enumeration via registration
    test_email = "test_unique_{{}}{{}}@example.com".format(
        "enum", "12345"
    )
    for ep in found_reg_endpoints:
        try:
            url = base_url.rstrip("/") + ep

            # Try registering with same email twice
            unique_id = "99887"
            email1 = f"enum_test_{{unique_id}}@example.com"
            email2 = f"enum_test_{{unique_id}}@example.com"

            resp1 = client.post(url, json={{
                "username": f"enum_user_1_{{unique_id}}",
                "email": email1,
                "password": "TestPass123!",
                "confirm_password": "TestPass123!",
            }})

            resp2 = client.post(url, json={{
                "username": f"enum_user_2_{{unique_id}}",
                "email": email2,
                "password": "TestPass123!",
                "confirm_password": "TestPass123!",
            }})

            # Check if duplicate email is detected
            if resp2.status_code in (200, 201, 302):
                results.append({{
                    "title": "Duplicate email registration accepted",
                    "description": f"Registration endpoint {{ep}} accepted duplicate email registration (status {{resp2.status_code}})",
                    "severity": "high",
                    "data": {{
                        "endpoint": ep,
                        "first_response_status": resp1.status_code,
                        "duplicate_response_status": resp2.status_code
                    }}
                }})
            elif "email" in resp2.text.lower() and ("exist" in resp2.text.lower() or "taken" in resp2.text.lower() or "already" in resp2.text.lower()):
                # Email enumeration possible via error message
                results.append({{
                    "title": "Email enumeration via registration response",
                    "description": f"Registration endpoint {{ep}} reveals whether email exists via error message",
                    "severity": "medium",
                    "data": {{
                        "endpoint": ep,
                        "response_contains_email_hint": True
                    }}
                }})

        except Exception:
            pass

    # Test username enumeration via registration
    for ep in found_reg_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            unique_id = "88776"

            resp1 = client.post(url, json={{
                "username": f"enumuser_{{unique_id}}",
                "email": f"enum1_{{unique_id}}@example.com",
                "password": "TestPass123!",
            }})

            resp2 = client.post(url, json={{
                "username": f"enumuser_{{unique_id}}",
                "email": f"enum2_{{unique_id}}@example.com",
                "password": "TestPass123!",
            }})

            if resp2.status_code in (200, 201, 302):
                results.append({{
                    "title": "Duplicate username registration accepted",
                    "description": f"Registration endpoint {{ep}} accepted duplicate username",
                    "severity": "high",
                    "data": {{
                        "endpoint": ep,
                        "duplicate_username_accepted": True
                    }}
                }})
            elif "username" in resp2.text.lower() and ("exist" in resp2.text.lower() or "taken" in resp2.text.lower() or "already" in resp2.text.lower()):
                results.append({{
                    "title": "Username enumeration via registration response",
                    "description": f"Registration endpoint {{ep}} reveals whether username exists",
                    "severity": "medium",
                    "data": {{
                        "endpoint": ep,
                        "username_enumeration_possible": True
                    }}
                }})

        except Exception:
            pass

    # Test weak email verification
    for ep in found_reg_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            unique_id = "77665"

            # Register with invalid email format
            resp_invalid = client.post(url, json={{
                "username": f"weak_email_{{unique_id}}",
                "email": "notanemail",
                "password": "TestPass123!",
            }})

            if resp_invalid.status_code in (200, 201, 302):
                results.append({{
                    "title": "Weak email validation on registration",
                    "description": f"Registration endpoint {{ep}} accepted invalid email format",
                    "severity": "medium",
                    "data": {{
                        "endpoint": ep,
                        "accepted_invalid_email": True
                    }}
                }})

            # Register with disposable email pattern
            resp_disposable = client.post(url, json={{
                "username": f"disposable_{{unique_id}}",
                "email": f"test_{{unique_id}}@tempmail.com",
                "password": "TestPass123!",
            }})

        except Exception:
            pass

    # Test registration without email verification
    for ep in found_reg_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            unique_id = "66554"

            resp = client.post(url, json={{
                "username": f"noverify_{{unique_id}}",
                "email": f"noverify_{{unique_id}}@example.com",
                "password": "TestPass123!",
            }})

            # Check if response indicates immediate access without verification
            if resp.status_code in (200, 201):
                if "verify" not in resp.text.lower() and "confirm" not in resp.text.lower() and "activation" not in resp.text.lower():
                    results.append({{
                        "title": "Registration may not require email verification",
                        "description": f"Registration endpoint {{ep}} returned success without mentioning email verification",
                        "severity": "low",
                        "data": {{
                            "endpoint": ep,
                            "response_status": resp.status_code,
                            "no_verification_mentioned": True
                        }}
                    }})

        except Exception:
            pass

    # Test rate limiting on registration
    for ep in found_reg_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            rate_limit_triggered = False
            for i in range(10):
                resp = client.post(url, json={{
                    "username": f"ratelimit_{{i}}_{{unique_id}}",
                    "email": f"ratelimit_{{i}}_{{unique_id}}@example.com",
                    "password": "TestPass123!",
                }})
                if resp.status_code in (429, 503):
                    rate_limit_triggered = True
                    break
                if "rate limit" in resp.text.lower() or "too many" in resp.text.lower():
                    rate_limit_triggered = True
                    break

            if not rate_limit_triggered:
                results.append({{
                    "title": "No rate limiting on registration",
                    "description": f"Registration endpoint {{ep}} did not trigger rate limiting after 10 rapid attempts",
                    "severity": "medium",
                    "data": {{
                        "endpoint": ep,
                        "attempts_before_check": 10
                    }}
                }})

        except Exception:
            pass

    # Test automated registration (check for bot protection)
    for ep in found_reg_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            resp = client.get(url)

            bot_protection = [
                r'g-recaptcha', r'h-captcha', r'cf-turnstile',
                r'akamai', r'bot.*detect', r'cloudflare.*challenge',
                r'data-sitekey', r'hcaptcha'
            ]
            has_protection = any(re.search(p, resp.text, re.IGNORECASE) for p in bot_protection)

            if not has_protection:
                results.append({{
                    "title": "No bot protection on registration",
                    "description": f"Registration endpoint {{ep}} lacks bot protection mechanisms",
                    "severity": "low",
                    "data": {{
                        "endpoint": ep,
                        "no_bot_protection": True
                    }}
                }})

        except Exception:
            pass

    client.close()

except Exception as e:
    results.append({{
        "title": "Registration testing error",
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
