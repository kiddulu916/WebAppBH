"""Role enumeration testing tool (WSTG-IDNT-01)."""

from workers.identity_mgmt.base_tool import IdentityMgmtTool
from workers.identity_mgmt.concurrency import WeightClass


class RoleEnumerator(IdentityMgmtTool):
    """Test for role enumeration vulnerabilities (WSTG-IDNT-01)."""

    name = "role_enumerator"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        import json as _json
        credentials_repr = _json.dumps(credentials) if credentials is not None else "None"

        script = f'''
import httpx
import json
import sys
import re

results = []
base_url = "{base_url}"

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    credentials = {credentials_repr}
    auth_headers = {{}}
    if credentials and credentials.get("token"):
        auth_headers["Authorization"] = f"Bearer {{credentials['token']}}"

    role_endpoints = [
        "/register", "/signup", "/profile", "/account",
        "/api/user", "/api/profile", "/api/account",
        "/users", "/api/users", "/admin", "/api/admin",
        "/settings", "/api/settings", "/dashboard",
        "/api/v1/user", "/api/v1/profile", "/api/v1/account",
        "/me", "/api/me", "/user/profile",
    ]

    role_patterns = [
        r'["\\']role["\\']\\s*[:=]\\s*["\\']?(\\w+)["\\']',
        r'["\\']user_type["\\']\\s*[:=]\\s*["\\']?(\\w+)["\\']',
        r'["\\']user_role["\\']\\s*[:=]\\s*["\\']?(\\w+)["\\']',
        r'["\\']is_admin["\\']\\s*[:=]\\s*(true|false)',
        r'["\\']is_superuser["\\']\\s*[:=]\\s*(true|false)',
        r'["\\']permissions["\\']\\s*[:=]',
        r'["\\']privileges["\\']\\s*[:=]',
        r'<input[^>]*name=["\\']role["\\']',
        r'<select[^>]*name=["\\']role["\\']',
        r'<input[^>]*name=["\\']user_type["\\']',
        r'hidden.*role',
        r'role.*admin',
        r'admin.*role',
    ]

    for endpoint in role_endpoints:
        try:
            url = base_url.rstrip("/") + endpoint

            resp = client.get(url, headers=auth_headers)
            content_type = resp.headers.get("content-type", "")

            all_roles = []
            for pattern in role_patterns:
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                if matches:
                    for m in matches:
                        val = m if isinstance(m, str) else m[0]
                        if val.lower() not in ("true", "false"):
                            all_roles.append(val.lower())
                        else:
                            all_roles.append(m)

            unique_roles = list(set(all_roles))

            if unique_roles:
                results.append({{
                    "title": "Role information disclosed in response",
                    "description": f"Found role/permission references in {{endpoint}}: {{', '.join(unique_roles[:10])}}",
                    "severity": "medium",
                    "data": {{
                        "endpoint": endpoint,
                        "roles_found": unique_roles[:10],
                        "status_code": resp.status_code,
                        "content_type": content_type
                    }}
                }})

            # Check for role parameter manipulation on registration endpoints
            if endpoint in ("/register", "/signup", "/api/register", "/api/signup"):
                for role_value in ["admin", "administrator", "superadmin", "moderator", "root", "superuser"]:
                    try:
                        resp_post = client.post(
                            url, headers=auth_headers,
                            json={{
                                "username": f"test_role_{{role_value}}",
                                "email": f"test_role_{{role_value}}@example.com",
                                "password": "TestPass123!",
                                "role": role_value,
                                "user_type": role_value,
                                "is_admin": True,
                            }}
                        )
                        resp_form = client.post(
                            url, headers=auth_headers,
                            data={{
                                "username": f"test_role_f_{{role_value}}",
                                "email": f"test_role_f_{{role_value}}@example.com",
                                "password": "TestPass123!",
                                "role": role_value,
                                "user_type": role_value,
                            }}
                        )
                        for r, fmt in [(resp_post, "json"), (resp_form, "form")]:
                            if r.status_code in (200, 201, 301, 302):
                                if role_value.lower() in r.text.lower() or "admin" in r.text.lower():
                                    results.append({{
                                        "title": "Potential role manipulation via registration",
                                        "description": f"Registration with role={{role_value}} ({{fmt}}) returned {{r.status_code}} and response contains role reference",
                                        "severity": "high",
                                        "data": {{
                                            "endpoint": endpoint,
                                            "tested_role": role_value,
                                            "format": fmt,
                                            "response_status": r.status_code
                                        }}
                                    }})
                    except Exception:
                        pass

            # Test role-based URL access
            admin_paths = ["/admin", "/admin/dashboard", "/admin/users", "/admin/settings",
                           "/administrator", "/manage", "/api/admin/users", "/api/admin/config"]
            for admin_path in admin_paths:
                try:
                    admin_url = base_url.rstrip("/") + admin_path
                    resp_unauth = client.get(admin_url)
                    if resp_unauth.status_code not in (401, 403, 404, 302):
                        results.append({{
                            "title": "Admin path accessible without authentication",
                            "description": f"Path {{admin_path}} returned status {{resp_unauth.status_code}} without auth",
                            "severity": "high",
                            "data": {{
                                "path": admin_path,
                                "status_code": resp_unauth.status_code
                            }}
                        }})
                except Exception:
                    pass

        except Exception as e:
            pass

    # Test API role enumeration via common API patterns
    api_endpoints = ["/api/v1/roles", "/api/roles", "/roles", "/api/v1/permissions",
                     "/api/permissions", "/permissions", "/api/v1/users?include=roles"]
    for api_ep in api_endpoints:
        try:
            url = base_url.rstrip("/") + api_ep
            resp = client.get(url, headers=auth_headers)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, dict) and any(k in data for k in ("roles", "permissions", "data")):
                        results.append({{
                            "title": "Role/permission enumeration via API",
                            "description": f"API endpoint {{api_ep}} returned role/permission data",
                            "severity": "medium",
                            "data": {{
                                "endpoint": api_ep,
                                "response_keys": list(data.keys())[:10]
                            }}
                        }})
                except Exception:
                    pass
        except Exception:
            pass

    # Block 5: JavaScript source scan (OWASP obj 1 — identify roles via source analysis)
    try:
        js_role_patterns = [
            "isAdmin", "ROLE_ADMIN", "hasRole", "requiresAdmin",
            "admin_required", "user_type", "userRole", "accessLevel",
            "requiresAuth", "adminOnly",
        ]
        home_resp = client.get(base_url.rstrip("/") + "/")
        script_srcs = re.findall('src="([^"]+)"', home_resp.text, re.IGNORECASE)
        abs_js_urls = []
        for src in script_srcs[:10]:
            if not src.endswith(".js") and ".js?" not in src:
                continue
            if src.startswith("http"):
                abs_js_urls.append(src)
            elif src.startswith("//"):
                abs_js_urls.append("https:" + src)
            elif src.startswith("/"):
                abs_js_urls.append(base_url.rstrip("/") + src)
            else:
                abs_js_urls.append(base_url.rstrip("/") + "/" + src)
        for js_url in abs_js_urls[:10]:
            try:
                js_resp = client.get(js_url, headers=auth_headers, timeout=5)
                if js_resp.status_code != 200:
                    continue
                matched_pats = [p for p in js_role_patterns if p.lower() in js_resp.text.lower()]
                if matched_pats:
                    results.append({{
                        "title": "Role/permission logic detected in JavaScript source",
                        "description": f"Found role-related patterns in {{js_url}}: {{', '.join(matched_pats)}}",
                        "severity": "medium",
                        "data": {{"js_url": js_url, "matched_patterns": matched_pats}},
                    }})
            except Exception:
                pass
    except Exception as js_err:
        results.append({{
            "title": "JS source scan error",
            "description": str(js_err),
            "severity": "info",
            "data": {{"error": str(js_err)}},
        }})

    client.close()

except Exception as e:
    results.append({{
        "title": "Role enumeration test error",
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
