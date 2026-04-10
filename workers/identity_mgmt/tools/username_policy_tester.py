"""Username policy testing tool (WSTG-IDENT-005)."""

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.concurrency import WeightClass


class UsernamePolicyTester(IdentityMgmtTool):
    """Test for weak username policies (WSTG-IDENT-005)."""

    name = "username_policy_tester"
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

    auth_headers = {{}}
    if credentials and credentials.get("token"):
        auth_headers["Authorization"] = f"Bearer {{credentials.get('token')}}"

    # Find registration endpoints
    reg_endpoints = [
        "/register", "/signup", "/api/register", "/api/signup",
        "/auth/register", "/auth/signup", "/api/v1/register",
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

    if not found_reg_eps:
        # Try to find any endpoint that accepts POST with username
        common_eps = ["/api/user", "/api/v1/user", "/users", "/api/users"]
        for ep in common_eps:
            try:
                url = base_url.rstrip("/") + ep
                resp = client.post(url, json={{"username": "test"}})
                if resp.status_code not in (404, 405):
                    found_reg_eps.append(ep)
            except Exception:
                pass

    unique_id = "11223"

    # ============================================================
    # 1. Test for weak username requirements
    # ============================================================
    weak_usernames = [
        "a", "1", "x", "aa", "11", "test", "user",
        "admin", "root", "administrator",
    ]

    for ep in found_reg_eps:
        try:
            url = base_url.rstrip("/") + ep

            for weak_un in weak_usernames:
                try:
                    resp = client.post(url, json={{
                        "username": f"{{weak_un}}_{{unique_id}}",
                        "email": f"weak_{{weak_un}}_{{unique_id}}@example.com",
                        "password": "TestPass123!",
                    }})

                    if resp.status_code in (200, 201, 302):
                        results.append({{
                            "title": "Weak username accepted",
                            "description": f"Registration endpoint {{ep}} accepted username '{{weak_un}}_{{unique_id}}'",
                            "severity": "medium",
                            "data": {{
                                "endpoint": ep,
                                "weak_username": f"{{weak_un}}_{{unique_id}}",
                                "response_status": resp.status_code
                            }}
                        }})
                except Exception:
                    pass

            # Test single character username
            for char in ["a", "1", "_"]:
                try:
                    resp = client.post(url, json={{
                        "username": f"{{char}}_{{unique_id}}",
                        "email": f"single_{{char}}_{{unique_id}}@example.com",
                        "password": "TestPass123!",
                    }})
                    if resp.status_code in (200, 201, 302):
                        results.append({{
                            "title": "Single character username accepted",
                            "description": f"Registration endpoint {{ep}} accepted single character username prefix",
                            "severity": "low",
                            "data": {{
                                "endpoint": ep,
                                "username": f"{{char}}_{{unique_id}}"
                            }}
                        }})
                except Exception:
                    pass

        except Exception:
            pass

    # ============================================================
    # 2. Test for reserved username usage
    # ============================================================
    reserved_usernames = [
        "admin", "administrator", "root", "superuser", "sysadmin",
        "webmaster", "postmaster", "hostmaster", "info", "support",
        "security", "abuse", "noreply", "no-reply", "notifications",
        "system", "service", "daemon", "operator", "manager",
        "moderator", "staff", "team", "help", "contact",
        "billing", "sales", "marketing", "hr", "legal",
        "api", "www", "mail", "ftp", "smtp", "pop", "imap",
    ]

    for ep in found_reg_eps:
        try:
            url = base_url.rstrip("/") + ep
            accepted_reserved = []

            for reserved in reserved_usernames:
                try:
                    resp = client.post(url, json={{
                        "username": reserved,
                        "email": f"{{reserved}}_{{unique_id}}@example.com",
                        "password": "TestPass123!",
                    }})

                    if resp.status_code in (200, 201, 302):
                        accepted_reserved.append(reserved)
                    elif resp.status_code == 409 or "taken" in resp.text.lower() or "exists" in resp.text.lower():
                        # Username taken - may be a reserved account that exists
                        results.append({{
                            "title": "Reserved username already registered",
                            "description": f"Reserved username '{{reserved}}' appears to be registered on {{ep}}",
                            "severity": "low",
                            "data": {{
                                "endpoint": ep,
                                "reserved_username": reserved
                            }}
                        }})
                except Exception:
                    pass

            if accepted_reserved:
                results.append({{
                    "title": "Reserved usernames accepted during registration",
                    "description": f"Registration endpoint {{ep}} accepted reserved usernames: {{', '.join(accepted_reserved[:5])}}",
                    "severity": "medium",
                    "data": {{
                        "endpoint": ep,
                        "accepted_reserved": accepted_reserved[:5]
                    }}
                }})

        except Exception:
            pass

    # ============================================================
    # 3. Test for username collision handling
    # ============================================================
    for ep in found_reg_eps:
        try:
            url = base_url.rstrip("/") + ep
            collision_username = f"collision_test_{{unique_id}}"

            # Register first time
            resp1 = client.post(url, json={{
                "username": collision_username,
                "email": f"collision1_{{unique_id}}@example.com",
                "password": "TestPass123!",
            }})

            # Try to register same username again
            resp2 = client.post(url, json={{
                "username": collision_username,
                "email": f"collision2_{{unique_id}}@example.com",
                "password": "TestPass123!",
            }})

            # Case variation
            resp3 = client.post(url, json={{
                "username": collision_username.upper(),
                "email": f"collision3_{{unique_id}}@example.com",
                "password": "TestPass123!",
            }})

            # Similar with dots/underscores
            resp4 = client.post(url, json={{
                "username": collision_username.replace("_", "."),
                "email": f"collision4_{{unique_id}}@example.com",
                "password": "TestPass123!",
            }})

            # Check if duplicate was accepted
            if resp2.status_code in (200, 201, 302):
                results.append({{
                    "title": "Username collision - duplicate accepted",
                    "description": f"Registration endpoint {{ep}} accepted duplicate username '{{collision_username}}'",
                    "severity": "high",
                    "data": {{
                        "endpoint": ep,
                        "username": collision_username,
                        "first_response": resp1.status_code,
                        "duplicate_response": resp2.status_code
                    }}
                }})

            # Check case sensitivity handling
            if resp3.status_code in (200, 201, 302) and resp1.status_code in (200, 201, 302):
                results.append({{
                    "title": "Case-insensitive username collision",
                    "description": f"Registration endpoint {{ep}} accepts both '{{collision_username}}' and '{{collision_username.upper()}}'",
                    "severity": "medium",
                    "data": {{
                        "endpoint": ep,
                        "original": collision_username,
                        "case_variant": collision_username.upper()
                    }}
                }})

        except Exception:
            pass

    # ============================================================
    # 4. Test for username impersonation risks
    # ============================================================
    impersonation_usernames = [
        "admin ", " admin", " admin ",  # Whitespace variations
        "Admin", "ADMIN", "AdMiN",  # Case variations
        "admin\u200b", "admin\u00a0",  # Unicode whitespace
        "admin.", ".admin",  # Dot variations
        "_admin", "admin_",  # Underscore variations
    ]

    for ep in found_reg_eps:
        try:
            url = base_url.rstrip("/") + ep

            for impersonate in impersonation_usernames:
                try:
                    resp = client.post(url, json={{
                        "username": impersonate,
                        "email": f"impersonate_{{unique_id}}@example.com",
                        "password": "TestPass123!",
                    }})

                    if resp.status_code in (200, 201, 302):
                        results.append({{
                            "title": "Username impersonation risk",
                            "description": f"Registration endpoint {{ep}} accepted username that could impersonate 'admin': '{{impersonate}}'",
                            "severity": "high",
                            "data": {{
                                "endpoint": ep,
                                "impersonation_username": repr(impersonate)
                            }}
                        }})
                except Exception:
                    pass

        except Exception:
            pass

    # ============================================================
    # 5. Test for Unicode homograph attacks
    # ============================================================
    homograph_usernames = [
        "admin",  # Cyrillic 'a' + Latin 'dmin'
        "admin",  # Greek alpha + Latin 'dmin'
        "user",  # Cyrillic 'u' + Latin 'ser'
        "root",  # Cyrillic 'o' + Latin 'rt'
        "test",  # Cyrillic 't' + Latin 'est'
        "support",  # Cyrillic 's' + Latin 'upport'
    ]

    for ep in found_reg_eps:
        try:
            url = base_url.rstrip("/") + ep

            for homograph in homograph_usernames:
                try:
                    resp = client.post(url, json={{
                        "username": homograph,
                        "email": f"homograph_{{unique_id}}@example.com",
                        "password": "TestPass123!",
                    }})

                    if resp.status_code in (200, 201, 302):
                        results.append({{
                            "title": "Unicode homograph username accepted",
                            "description": f"Registration endpoint {{ep}} accepted Unicode homograph username",
                            "severity": "medium",
                            "data": {{
                                "endpoint": ep,
                                "homograph_username": repr(homograph),
                                "looks_like": homograph.encode('ascii', 'ignore').decode('ascii')
                            }}
                        }})
                except Exception:
                    pass

        except Exception:
            pass

    # ============================================================
    # 6. Test for username length limits
    # ============================================================
    length_tests = [
        ("a" * 1, "1_char"),
        ("a" * 2, "2_chars"),
        ("a" * 255, "255_chars"),
        ("a" * 500, "500_chars"),
        ("a" * 1000, "1000_chars"),
        ("a" * 10000, "10000_chars"),
    ]

    for ep in found_reg_eps:
        try:
            url = base_url.rstrip("/") + ep

            for test_un, label in length_tests:
                try:
                    resp = client.post(url, json={{
                        "username": test_un,
                        "email": f"length_{{label}}_{{unique_id}}@example.com",
                        "password": "TestPass123!",
                    }})

                    if resp.status_code in (200, 201, 302):
                        results.append({{
                            "title": "Long username accepted",
                            "description": f"Registration endpoint {{ep}} accepted {{label}} username",
                            "severity": "low" if len(test_un) <= 255 else "medium",
                            "data": {{
                                "endpoint": ep,
                                "length_label": label,
                                "username_length": len(test_un),
                                "response_status": resp.status_code
                            }}
                        }})
                    elif resp.status_code == 500:
                        results.append({{
                            "title": "Server error on long username",
                            "description": f"Registration endpoint {{ep}} returned 500 for {{label}} username - possible buffer issue",
                            "severity": "high",
                            "data": {{
                                "endpoint": ep,
                                "length_label": label,
                                "username_length": len(test_un)
                            }}
                        }})
                except Exception:
                    pass

        except Exception:
            pass

    # ============================================================
    # 7. Test for special character handling in usernames
    # ============================================================
    special_char_usernames = [
        ("user<script>alert(1)</script>", "xss_attempt"),
        ("user' OR '1'='1", "sql_injection"),
        ("user; ls -la", "command_injection"),
        ("user{{{{config}}}}", "template_injection"),
        ("user/../etc/passwd", "path_traversal"),
        ("user%00null", "null_byte"),
        ("user\\n\\r", "newline_injection"),
        ("<img src=x onerror=alert(1)>", "xss_img"),
        ("user\" onclick=\"alert(1)", "xss_attr"),
        ("${{7*7}}", "ssti"),
        ("{{7*7}}", "jinja_ssti"),
        ("user@domain.com", "email_as_username"),
        ("user name", "space_in_username"),
        ("user\tname", "tab_in_username"),
    ]

    for ep in found_reg_eps:
        try:
            url = base_url.rstrip("/") + ep

            for special_un, attack_type in special_char_usernames:
                try:
                    resp = client.post(url, json={{
                        "username": special_un,
                        "email": f"special_{{unique_id}}@example.com",
                        "password": "TestPass123!",
                    }})

                    if resp.status_code in (200, 201, 302):
                        severity = "medium"
                        if "xss" in attack_type or "injection" in attack_type:
                            severity = "high"

                        results.append({{
                            "title": f"Special character username accepted ({{attack_type}})",
                            "description": f"Registration endpoint {{ep}} accepted username with {{attack_type}} payload",
                            "severity": severity,
                            "data": {{
                                "endpoint": ep,
                                "attack_type": attack_type,
                                "username": repr(special_un)[:100]
                            }}
                        }})
                    elif resp.status_code == 500:
                        results.append({{
                            "title": f"Server error on special character username",
                            "description": f"Registration endpoint {{ep}} returned 500 for {{attack_type}} payload",
                            "severity": "high",
                            "data": {{
                                "endpoint": ep,
                                "attack_type": attack_type,
                                "username": repr(special_un)[:100]
                            }}
                        }})
                except Exception:
                    pass

        except Exception:
            pass

    client.close()

except Exception as e:
    results.append({{
        "title": "Username policy test error",
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
