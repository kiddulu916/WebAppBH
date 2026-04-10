"""Account provisioning testing tool (WSTG-IDENT-003)."""

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.concurrency import WeightClass


class AccountProvisionTester(IdentityMgmtTool):
    """Test account provisioning mechanisms (WSTG-IDENT-003)."""

    name = "account_provision_tester"
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

    # Test privilege escalation during account creation
    provision_endpoints = [
        "/api/users", "/api/v1/users", "/api/accounts", "/api/v1/accounts",
        "/admin/users", "/api/admin/users", "/users/create", "/api/users/create",
        "/register", "/api/register", "/signup", "/api/signup",
    ]

    found_endpoints = []
    for ep in provision_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            resp = client.get(url, headers=auth_headers)
            if resp.status_code in (200, 405):  # 405 means POST might work
                found_endpoints.append(ep)
        except Exception:
            pass

    for ep in found_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            unique_id = "55443"

            # Test mass assignment - try to set privileged fields during registration
            mass_assignment_payloads = [
                {{
                    "username": f"mass_assign_{{unique_id}}",
                    "email": f"mass_{{unique_id}}@example.com",
                    "password": "TestPass123!",
                    "role": "admin",
                    "is_admin": True,
                    "user_type": "admin",
                    "permissions": ["admin", "write", "delete"],
                    "account_type": "premium",
                    "subscription": "admin",
                }},
                {{
                    "username": f"mass_assign2_{{unique_id}}",
                    "email": f"mass2_{{unique_id}}@example.com",
                    "password": "TestPass123!",
                    "role": "superadmin",
                    "is_superuser": True,
                    "privileges": "all",
                    "access_level": 999,
                }},
            ]

            for payload in mass_assignment_payloads:
                try:
                    resp = client.post(url, json=payload, headers=auth_headers)
                    if resp.status_code in (200, 201, 302):
                        # Check if privileged fields were accepted
                        resp_text_lower = resp.text.lower()
                        privileged_indicators = ["admin", "superadmin", "superuser", "privilege"]
                        found_indicators = [i for i in privileged_indicators if i in resp_text_lower]

                        if found_indicators:
                            results.append({{
                                "title": "Potential mass assignment vulnerability",
                                "description": f"Endpoint {{ep}} accepted registration with privileged fields. Indicators found: {{', '.join(found_indicators)}}",
                                "severity": "high",
                                "data": {{
                                    "endpoint": ep,
                                    "payload_keys": list(payload.keys()),
                                    "response_status": resp.status_code,
                                    "privileged_indicators": found_indicators
                                }}
                            }})
                        else:
                            results.append({{
                                "title": "Registration accepted extra fields",
                                "description": f"Endpoint {{ep}} accepted registration with additional fields (status {{resp.status_code}})",
                                "severity": "low",
                                "data": {{
                                    "endpoint": ep,
                                    "payload_keys": list(payload.keys()),
                                    "response_status": resp.status_code
                                }}
                            }})
                except Exception:
                    pass

        except Exception:
            pass

    # Test default role assignment security
    for ep in found_endpoints:
        if ep in ("/register", "/api/register", "/signup", "/api/signup"):
            try:
                url = base_url.rstrip("/") + ep
                unique_id = "44332"

                # Register with minimal fields to check default role
                resp = client.post(url, json={{
                    "username": f"default_role_{{unique_id}}",
                    "email": f"default_{{unique_id}}@example.com",
                    "password": "TestPass123!",
                }})

                if resp.status_code in (200, 201, 302):
                    # Check what role was assigned by default
                    resp_lower = resp.text.lower()
                    default_roles = ["user", "member", "basic", "standard"]
                    found_default = [r for r in default_roles if r in resp_lower]

                    # Check if any elevated role was assigned
                    elevated_roles = ["admin", "moderator", "editor", "manager"]
                    found_elevated = [r for r in elevated_roles if r in resp_lower]

                    if found_elevated:
                        results.append({{
                            "title": "Elevated default role assignment",
                            "description": f"Registration on {{ep}} may have assigned elevated role: {{', '.join(found_elevated)}}",
                            "severity": "high",
                            "data": {{
                                "endpoint": ep,
                                "elevated_roles_found": found_elevated
                            }}
                        }})

            except Exception:
                pass

    # Test account provisioning API exposure
    admin_provision_endpoints = [
        "/api/v1/admin/users", "/api/admin/users", "/admin/api/users",
        "/api/v1/provision", "/api/provision", "/provision",
        "/api/v1/accounts", "/api/accounts",
        "/api/internal/users", "/internal/api/users",
    ]

    for ep in admin_provision_endpoints:
        try:
            url = base_url.rstrip("/") + ep

            # Test without authentication
            resp_unauth = client.get(url)
            if resp_unauth.status_code not in (401, 403, 404, 302):
                results.append({{
                    "title": "Account provisioning endpoint accessible without auth",
                    "description": f"Endpoint {{ep}} returned status {{resp_unauth.status_code}} without authentication",
                    "severity": "high",
                    "data": {{
                        "endpoint": ep,
                        "status_code": resp_unauth.status_code
                    }}
                }})

            # Test POST without authentication
            resp_post_unauth = client.post(url, json={{
                "username": "unauth_provision",
                "email": "unauth@example.com",
                "password": "TestPass123!",
            }})
            if resp_post_unauth.status_code in (200, 201, 302):
                results.append({{
                    "title": "Account creation without authentication",
                    "description": f"Endpoint {{ep}} allowed account creation without auth (status {{resp_post_unauth.status_code}})",
                    "severity": "critical",
                    "data": {{
                        "endpoint": ep,
                        "response_status": resp_post_unauth.status_code
                    }}
                }})

        except Exception:
            pass

    # Test account activation bypass
    activation_endpoints = [
        "/activate", "/api/activate", "/api/v1/activate",
        "/verify", "/api/verify", "/api/v1/verify",
        "/confirm", "/api/confirm", "/api/v1/confirm",
        "/api/v1/users/activate", "/api/users/activate",
    ]

    for ep in activation_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            unique_id = "33221"

            # Try to activate a non-existent account
            resp = client.post(url, json={{
                "user_id": "999999",
                "token": "fake_token_{{unique_id}}",
                "email": f"fake_{{unique_id}}@example.com",
            }})

            # Try with empty/missing token
            resp_empty = client.post(url, json={{
                "user_id": "999999",
                "token": "",
            }})

            resp_no_token = client.post(url, json={{
                "user_id": "999999",
            }})

            # If any of these succeed, there may be an activation bypass
            for r, test_type in [(resp, "fake_token"), (resp_empty, "empty_token"), (resp_no_token, "no_token")]:
                if r.status_code in (200, 201, 302):
                    if "error" not in r.text.lower() and "invalid" not in r.text.lower():
                        results.append({{
                            "title": "Potential account activation bypass",
                            "description": f"Activation endpoint {{ep}} may have accepted {{test_type}} (status {{r.status_code}})",
                            "severity": "high",
                            "data": {{
                                "endpoint": ep,
                                "test_type": test_type,
                                "response_status": r.status_code
                            }}
                        }})

        except Exception:
            pass

    # Test account provisioning without proper authorization
    if credentials and credentials.get("token"):
        # Test with low-privilege token trying to provision accounts
        for ep in admin_provision_endpoints:
            try:
                url = base_url.rstrip("/") + ep
                resp = client.post(url, json={{
                    "username": "auth_test_user",
                    "email": "auth_test@example.com",
                    "password": "TestPass123!",
                    "role": "admin",
                }}, headers=auth_headers)

                if resp.status_code in (200, 201, 302):
                    results.append({{
                        "title": "Account provisioning with provided credentials",
                        "description": f"Endpoint {{ep}} allowed account creation with provided credentials (status {{resp.status_code}})",
                        "severity": "medium",
                        "data": {{
                            "endpoint": ep,
                            "response_status": resp.status_code
                        }}
                    }})
                elif resp.status_code == 403:
                    # Good - properly forbidden
                    pass
                elif resp.status_code == 401:
                    results.append({{
                        "title": "Auth token not accepted for provisioning",
                        "description": f"Endpoint {{ep}} returned 401 with provided token",
                        "severity": "info",
                        "data": {{
                            "endpoint": ep,
                            "response_status": resp.status_code
                        }}
                    }})

            except Exception:
                pass

    client.close()

except Exception as e:
    results.append({{
        "title": "Account provisioning test error",
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
