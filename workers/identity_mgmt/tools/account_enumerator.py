"""Account enumeration testing tool (WSTG-IDENT-004)."""

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.concurrency import WeightClass


class AccountEnumerator(IdentityMgmtTool):
    """Test for account enumeration vulnerabilities (WSTG-IDENT-004)."""

    name = "account_enumerator"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import sys
import re
import time

results = []
base_url = "{base_url}"

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    auth_headers = {{}}
    if credentials and credentials.get("token"):
        auth_headers["Authorization"] = f"Bearer {{credentials.get('token')}}"

    # Common usernames and emails for testing
    test_usernames = ["admin", "administrator", "root", "user", "test", "info", "support", "webmaster"]
    test_emails = [
        "admin@example.com", "root@example.com", "test@example.com",
        "info@example.com", "support@example.com", "admin@{{base_url.split('://')[-1].split('/')[0]}}",
    ]

    # ============================================================
    # 1. Username enumeration via login responses
    # ============================================================
    login_endpoints = [
        "/login", "/signin", "/auth/login", "/api/login", "/api/v1/login",
        "/api/auth/login", "/user/login", "/account/login",
    ]

    found_login_eps = []
    for ep in login_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            resp = client.get(url)
            if resp.status_code == 200:
                found_login_eps.append(ep)
        except Exception:
            pass

    for ep in found_login_eps:
        try:
            url = base_url.rstrip("/") + ep
            responses = {{}}

            for username in test_usernames[:5]:  # Limit to first 5 for speed
                try:
                    resp = client.post(url, json={{
                        "username": username,
                        "password": "WrongPassword123!",
                    }})
                    responses[username] = {{
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "text": resp.text[:500],
                    }}
                except Exception:
                    pass

            # Compare responses for differences
            if len(responses) >= 2:
                status_codes = set(r["status"] for r in responses.values())
                lengths = set(r["length"] for r in responses.values())

                # Different status codes for valid vs invalid users
                if len(status_codes) > 1:
                    results.append({{
                        "title": "Username enumeration via login status codes",
                        "description": f"Login endpoint {{ep}} returns different status codes for different usernames: {{status_codes}}",
                        "severity": "high",
                        "data": {{
                            "endpoint": ep,
                            "status_codes": list(status_codes),
                            "usernames_tested": list(responses.keys())
                        }}
                    }})

                # Different response lengths indicate different messages
                elif len(lengths) > 1:
                    # Check if response content differs meaningfully
                    texts = {{u: r["text"] for u, r in responses.items()}}
                    unique_texts = set()
                    for t in texts.values():
                        # Normalize for comparison
                        normalized = t.lower().replace("invalid", "").replace("incorrect", "").replace("wrong", "")
                        unique_texts.add(normalized[:200])

                    if len(unique_texts) > 1:
                        results.append({{
                            "title": "Username enumeration via login response content",
                            "description": f"Login endpoint {{ep}} returns different error messages for different usernames",
                            "severity": "high",
                            "data": {{
                                "endpoint": ep,
                                "response_lengths": {{u: r["length"] for u, r in responses.items()}},
                                "usernames_tested": list(responses.keys())
                            }}
                        }})

        except Exception:
            pass

    # ============================================================
    # 2. Email enumeration via login responses
    # ============================================================
    for ep in found_login_eps:
        try:
            url = base_url.rstrip("/") + ep
            email_responses = {{}}

            for email in test_emails[:5]:
                try:
                    resp = client.post(url, json={{
                        "email": email,
                        "password": "WrongPassword123!",
                    }})
                    email_responses[email] = {{
                        "status": resp.status_code,
                        "length": len(resp.text),
                    }}
                except Exception:
                    pass

            if len(email_responses) >= 2:
                statuses = set(r["status"] for r in email_responses.values())
                lengths = set(r["length"] for r in email_responses.values())

                if len(statuses) > 1 or len(lengths) > 1:
                    results.append({{
                        "title": "Email enumeration via login response",
                        "description": f"Login endpoint {{ep}} may allow email enumeration via response differences",
                        "severity": "high",
                        "data": {{
                            "endpoint": ep,
                            "status_codes": list(statuses),
                            "response_lengths": {{e: r["length"] for e, r in email_responses.items()}}
                        }}
                    }})

        except Exception:
            pass

    # ============================================================
    # 3. Enumeration via forgot password flow
    # ============================================================
    forgot_endpoints = [
        "/forgot-password", "/forgot", "/reset-password", "/password-reset",
        "/api/forgot-password", "/api/reset-password", "/auth/forgot-password",
        "/account/forgot-password", "/user/forgot-password",
    ]

    found_forgot_eps = []
    for ep in forgot_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            resp = client.get(url)
            if resp.status_code == 200:
                found_forgot_eps.append(ep)
        except Exception:
            pass

    for ep in found_forgot_eps:
        try:
            url = base_url.rstrip("/") + ep
            responses = {{}}

            for email in test_emails[:5]:
                try:
                    resp = client.post(url, json={{"email": email}})
                    responses[email] = {{
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "text_lower": resp.text.lower()[:500],
                    }}
                except Exception:
                    pass

            if len(responses) >= 2:
                # Check for different responses
                statuses = set(r["status"] for r in responses.values())
                lengths = set(r["length"] for r in responses.values())

                # Check for email existence disclosure
                email_found_msgs = []
                for email, r in responses.items():
                    indicators = ["sent", "found", "exists", "registered", "active"]
                    not_found_msgs = ["not found", "not exist", "no account", "not registered"]

                    has_found = any(ind in r["text_lower"] for ind in indicators)
                    has_not_found = any(msg in r["text_lower"] for msg in not_found_msgs)

                    if has_found and not has_not_found:
                        email_found_msgs.append(email)
                    elif has_not_found and not has_found:
                        pass  # Email not found - normal
                    elif has_found and has_not_found:
                        pass  # Generic message - good

                if email_found_msgs:
                    results.append({{
                        "title": "Email enumeration via forgot password",
                        "description": f"Forgot password endpoint {{ep}} reveals email existence for: {{', '.join(email_found_msgs[:3])}}",
                        "severity": "high",
                        "data": {{
                            "endpoint": ep,
                            "emails_confirmed": email_found_msgs[:3]
                        }}
                    }})

                if len(statuses) > 1 or len(lengths) > 1:
                    results.append({{
                        "title": "Forgot password response differences",
                        "description": f"Forgot password endpoint {{ep}} returns different responses for different emails",
                        "severity": "medium",
                        "data": {{
                            "endpoint": ep,
                            "status_codes": list(statuses),
                            "response_lengths": {{e: r["length"] for e, r in responses.items()}}
                        }}
                    }})

        except Exception:
            pass

    # ============================================================
    # 4. Enumeration via registration responses
    # ============================================================
    reg_endpoints = [
        "/register", "/signup", "/api/register", "/api/signup",
        "/auth/register", "/auth/signup",
    ]

    found_reg_eps = []
    for ep in reg_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            resp = client.get(url)
            if resp.status_code == 200:
                found_reg_eps.append(ep)
        except Exception:
            pass

    for ep in found_reg_eps:
        try:
            url = base_url.rstrip("/") + ep
            responses = {{}}

            for username in test_usernames[:5]:
                try:
                    resp = client.post(url, json={{
                        "username": username,
                        "email": f"{{username}}_enum_{{int(time.time())}}@example.com",
                        "password": "TestPass123!",
                    }})
                    responses[username] = {{
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "text_lower": resp.text.lower()[:500],
                    }}
                except Exception:
                    pass

            if len(responses) >= 2:
                for username, r in responses.items():
                    if "taken" in r["text_lower"] or "exists" in r["text_lower"] or "already" in r["text_lower"]:
                        results.append({{
                            "title": "Username enumeration via registration",
                            "description": f"Registration endpoint {{ep}} reveals username '{{username}}' already exists",
                            "severity": "medium",
                            "data": {{
                                "endpoint": ep,
                                "enumerated_username": username
                            }}
                        }})

        except Exception:
            pass

    # ============================================================
    # 5. Enumeration via error messages
    # ============================================================
    all_eps = found_login_eps + found_forgot_eps + found_reg_eps
    for ep in all_eps:
        try:
            url = base_url.rstrip("/") + ep
            # Test with various malformed inputs
            test_cases = [
                {{}},  # Empty body
                {{"username": ""}},  # Empty username
                {{"email": ""}},  # Empty email
                {{"username": "a" * 1000}},  # Very long username
            ]

            for tc in test_cases:
                try:
                    resp = client.post(url, json=tc)
                    if resp.status_code == 200 and "error" in resp.text.lower():
                        # Verbose error message
                        results.append({{
                            "title": "Verbose error message on {{ep}}",
                            "description": f"Endpoint {{ep}} returned detailed error message that may aid enumeration",
                            "severity": "low",
                            "data": {{
                                "endpoint": ep,
                                "test_case": str(tc)[:100]
                            }}
                        }})
                        break
                except Exception:
                    pass

        except Exception:
            pass

    # ============================================================
    # 6. Response timing differences
    # ============================================================
    for ep in found_login_eps:
        try:
            url = base_url.rstrip("/") + ep
            timings = {{}}

            for username in test_usernames[:3]:
                try:
                    start = time.time()
                    client.post(url, json={{
                        "username": username,
                        "password": "WrongPassword123!",
                    }})
                    elapsed = time.time() - start
                    timings[username] = elapsed
                except Exception:
                    pass

            if len(timings) >= 2:
                times = list(timings.values())
                max_time = max(times)
                min_time = min(times)

                # Significant timing difference (>50ms) may indicate enumeration
                if (max_time - min_time) > 0.05:
                    results.append({{
                        "title": "Potential timing-based enumeration",
                        "description": f"Login endpoint {{ep}} shows timing differences: max={{max_time:.3f}}s, min={{min_time:.3f}}s",
                        "severity": "medium",
                        "data": {{
                            "endpoint": ep,
                            "timings": {{u: f"{{t:.3f}}s" for u, t in timings.items()}},
                            "time_difference": f"{{max_time - min_time:.3f}}s"
                        }}
                    }})

        except Exception:
            pass

    # ============================================================
    # 7. Enumeration via profile page access
    # ============================================================
    profile_patterns = [
        "/profile/{{username}}", "/user/{{username}}", "/users/{{username}}",
        "/members/{{username}}", "/account/{{username}}",
        "/api/user/{{username}}", "/api/users/{{username}}",
        "/~{{username}}", "/u/{{username}}",
    ]

    for pattern in profile_patterns:
        try:
            found_profiles = []
            for username in test_usernames[:5]:
                try:
                    path = pattern.replace("{{username}}", username)
                    url = base_url.rstrip("/") + path
                    resp = client.get(url)
                    if resp.status_code == 200:
                        found_profiles.append(username)
                except Exception:
                    pass

            if found_profiles:
                results.append({{
                    "title": "User profiles accessible via URL pattern",
                    "description": f"Profile pattern {{pattern}} returned 200 for usernames: {{', '.join(found_profiles)}}",
                    "severity": "medium",
                    "data": {{
                        "pattern": pattern,
                        "accessible_profiles": found_profiles
                    }}
                }})

        except Exception:
            pass

    client.close()

except Exception as e:
    results.append({{
        "title": "Account enumeration test error",
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
